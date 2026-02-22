use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ble::{
    SessionBootstrapOptions, SessionPhase as WalletSessionPhase, advance_session_bootstrap,
    advance_to_paired_with_policy, backend_from_session, connect_and_bootstrap_session,
    connect_trezor_device, scan_trezor, session_phase, session_state as build_session_state,
    workflow as new_workflow, workflow_with_storage,
};
use hw_wallet::btc::{
    build_sign_tx_request as build_btc_sign_tx_request, parse_tx_json as parse_btc_tx_json,
};
use hw_wallet::eip712::{
    build_sign_typed_data_request, build_sign_typed_hash_request, normalize_typed_data_signature,
};
use hw_wallet::eth::{TxAccessListInput, TxInput, build_sign_tx_request, verify_sign_tx_response};
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::message::{
    SignatureEncoding as WalletSignatureEncoding, build_sign_message_request,
    normalize_message_signature,
};
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::timeout;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::types::PairingPrompt as ThpPairingPrompt;
use trezor_connect::thp::{
    FileStorage, GetAddressRequest as ThpGetAddressRequest, PairingController, PairingDecision,
    PairingMethod as ThpPairingMethod, Phase, SignMessageRequest as ThpSignMessageRequest,
    ThpWorkflow, ThpWorkflowError,
};

use crate::errors::HWCoreError;
use crate::types::{
    AccessListEntry, AddressResult, BleDeviceInfo, GetAddressRequest, HandshakeCache, HostConfig,
    PairingProgress, PairingProgressKind, PairingPrompt, SessionHandshakeState, SessionRetryPolicy,
    SessionState, SignMessageRequest, SignMessageResult, SignTxRequest, SignTxResult,
    SignTypedDataRequest, SignTypedDataResult, SignatureEncoding, ThpState, WorkflowEvent,
    WorkflowEventKind,
};

const DEFAULT_THP_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_SOLANA_SERIALIZED_TX_BYTES: usize = 16;

fn bootstrap_options(
    try_to_unlock: bool,
    retry_policy: Option<SessionRetryPolicy>,
) -> SessionBootstrapOptions {
    SessionBootstrapOptions {
        thp_timeout: DEFAULT_THP_TIMEOUT,
        try_to_unlock,
        passphrase: None,
        on_device: false,
        derive_cardano: false,
        retry_policy: retry_policy.unwrap_or_default(),
    }
}

fn storage_from_path(storage_path: String) -> Result<Arc<dyn ThpStorage>, HWCoreError> {
    let trimmed = storage_path.trim();
    if trimmed.is_empty() {
        return Err(HWCoreError::Validation(
            "storage path must not be empty".to_string(),
        ));
    }
    Ok(Arc::new(FileStorage::new(PathBuf::from(trimmed))) as Arc<dyn ThpStorage>)
}

struct CodeEntryPairingController {
    code: Mutex<Option<String>>,
}

impl CodeEntryPairingController {
    fn new(code: String) -> Self {
        Self {
            code: Mutex::new(Some(code)),
        }
    }
}

#[async_trait::async_trait]
impl PairingController for CodeEntryPairingController {
    async fn on_prompt(
        &self,
        prompt: ThpPairingPrompt,
    ) -> std::result::Result<PairingDecision, String> {
        if !prompt
            .available_methods
            .contains(&ThpPairingMethod::CodeEntry)
        {
            return Err("device does not offer code-entry pairing".to_string());
        }

        if prompt.selected_method != ThpPairingMethod::CodeEntry {
            return Ok(PairingDecision::SwitchMethod(ThpPairingMethod::CodeEntry));
        }

        let code = self.code.lock().take().ok_or_else(|| {
            "pairing code already used; submit a fresh code with pairing_submit_code".to_string()
        })?;
        Ok(PairingDecision::SubmitTag {
            method: ThpPairingMethod::CodeEntry,
            tag: code,
        })
    }
}

fn pairing_start_for_state(
    state: &trezor_connect::thp::ThpState,
) -> Result<PairingPrompt, HWCoreError> {
    if state.phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_start requires Pairing phase".to_string(),
        ));
    }

    let methods = state
        .handshake_credentials()
        .map(|credentials| credentials.pairing_methods.clone())
        .or_else(|| {
            state
                .handshake_cache()
                .map(|cache| cache.pairing_methods.clone())
        })
        .unwrap_or_default();
    let message = if state.is_paired() {
        "Connection confirmation is required for this already-paired device".to_string()
    } else if methods.contains(&ThpPairingMethod::CodeEntry) {
        "Enter the 6-digit code shown on the Trezor to finish pairing".to_string()
    } else {
        "Complete pairing on the device to finish connecting".to_string()
    };

    Ok(PairingPrompt {
        available_methods: methods,
        selected_method: state.pairing_method(),
        requires_connection_confirmation: state.is_paired(),
        message,
    })
}

async fn pairing_confirm_connection_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
) -> Result<PairingProgress, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    if workflow.state().phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_confirm_connection requires Pairing phase".to_string(),
        ));
    }
    if !workflow.state().is_paired() {
        return Err(HWCoreError::Validation(
            "device is not in paired-confirmation state; use pairing_submit_code".to_string(),
        ));
    }

    workflow.pairing(None).await.map_err(HWCoreError::from)?;
    Ok(PairingProgress {
        kind: PairingProgressKind::Completed,
        message: "Paired connection confirmed".to_string(),
    })
}

async fn pairing_submit_code_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    code: String,
) -> Result<PairingProgress, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    if workflow.state().phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_submit_code requires Pairing phase".to_string(),
        ));
    }
    if workflow.state().is_paired() {
        return Err(HWCoreError::Validation(
            "device expects connection confirmation; use pairing_confirm_connection".to_string(),
        ));
    }

    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(HWCoreError::Validation(
            "pairing code must be exactly 6 digits".to_string(),
        ));
    }

    match workflow
        .submit_code_entry_pairing_tag(trimmed.to_string())
        .await
    {
        Ok(()) => {}
        Err(ThpWorkflowError::PairingInteractionRequired) => {
            let controller = CodeEntryPairingController::new(trimmed.to_string());
            workflow
                .pairing(Some(&controller))
                .await
                .map_err(HWCoreError::from)?;
        }
        Err(err) => return Err(HWCoreError::from(err)),
    }

    Ok(PairingProgress {
        kind: PairingProgressKind::Completed,
        message: "Pairing completed".to_string(),
    })
}

fn map_get_address_request(
    request: GetAddressRequest,
) -> Result<ThpGetAddressRequest, HWCoreError> {
    let path = parse_bip32_path(&request.path).map_err(HWCoreError::from)?;
    Ok(ThpGetAddressRequest {
        chain: request.chain,
        path,
        show_display: request.show_on_device,
        chunkify: request.chunkify,
        encoded_network: None,
        include_public_key: request.include_public_key,
    })
}

async fn get_address_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: GetAddressRequest,
) -> Result<AddressResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let thp_request = map_get_address_request(request)?;
    let response = workflow
        .get_address(thp_request)
        .await
        .map_err(HWCoreError::from)?;
    Ok(AddressResult {
        chain: response.chain,
        address: response.address,
        public_key: response.public_key,
    })
}

fn map_sign_tx_request(
    request: SignTxRequest,
) -> Result<trezor_connect::thp::SignTxRequest, HWCoreError> {
    match request.chain {
        crate::types::Chain::Ethereum => {
            let path = parse_bip32_path(&request.path).map_err(HWCoreError::from)?;
            let tx = TxInput {
                to: request.to,
                value: request.value,
                nonce: request.nonce,
                gas_limit: request.gas_limit,
                chain_id: request.chain_id,
                data: request.data,
                max_fee_per_gas: request.max_fee_per_gas,
                max_priority_fee: request.max_priority_fee,
                access_list: request
                    .access_list
                    .into_iter()
                    .map(|entry: AccessListEntry| TxAccessListInput {
                        address: entry.address,
                        storage_keys: entry.storage_keys,
                    })
                    .collect(),
            };

            let mut sign_request = build_sign_tx_request(path, tx).map_err(HWCoreError::from)?;
            sign_request.chunkify = request.chunkify;
            Ok(sign_request)
        }
        crate::types::Chain::Solana => {
            let path = parse_bip32_path(&request.path).map_err(HWCoreError::from)?;
            let serialized_tx = decode_hex(&request.data).map_err(HWCoreError::from)?;
            if serialized_tx.len() < MIN_SOLANA_SERIALIZED_TX_BYTES {
                return Err(HWCoreError::Validation(format!(
                    "solana serialized tx is too short ({} bytes); provide full serialized transaction bytes",
                    serialized_tx.len()
                )));
            }
            Ok(trezor_connect::thp::SignTxRequest::solana(
                path,
                serialized_tx,
            ))
        }
        crate::types::Chain::Bitcoin => {
            let tx = parse_btc_tx_json(&request.data).map_err(HWCoreError::from)?;
            build_btc_sign_tx_request(tx).map_err(HWCoreError::from)
        }
    }
}

fn map_sign_message_request(
    request: SignMessageRequest,
) -> Result<ThpSignMessageRequest, HWCoreError> {
    let path = parse_bip32_path(&request.path).map_err(HWCoreError::from)?;
    build_sign_message_request(
        request.chain,
        path,
        &request.message,
        request.is_hex,
        request.chunkify,
    )
    .map_err(HWCoreError::from)
}

fn map_sign_typed_data_request(
    request: SignTypedDataRequest,
) -> Result<trezor_connect::thp::SignTypedDataRequest, HWCoreError> {
    if request.chain != crate::types::Chain::Ethereum {
        return Err(HWCoreError::Validation(
            "typed-data signing currently supports Ethereum only".to_string(),
        ));
    }

    let path = parse_bip32_path(&request.path).map_err(HWCoreError::from)?;
    if let Some(data_json) = request.data_json {
        return build_sign_typed_data_request(path, &data_json, request.metamask_v4_compat)
            .map_err(HWCoreError::from);
    }

    build_sign_typed_hash_request(
        path,
        &request.domain_separator_hash,
        request.message_hash.as_deref(),
    )
    .map_err(HWCoreError::from)
}

async fn sign_tx_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTxRequest,
) -> Result<SignTxResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let chain = request.chain;
    let sign_request = map_sign_tx_request(request)?;
    let response = workflow
        .sign_tx(sign_request.clone())
        .await
        .map_err(HWCoreError::from)?;
    let verification = verify_sign_tx_response(&sign_request, &response).ok();
    Ok(SignTxResult {
        chain,
        v: response.v,
        r: response.r,
        s: response.s,
        tx_hash: verification.as_ref().map(|sig| sig.tx_hash.to_vec()),
        recovered_address: verification.map(|sig| sig.recovered_address),
    })
}

fn map_signature_encoding(encoding: WalletSignatureEncoding) -> SignatureEncoding {
    match encoding {
        WalletSignatureEncoding::Hex => SignatureEncoding::Hex,
        WalletSignatureEncoding::Base64 => SignatureEncoding::Base64,
    }
}

async fn sign_message_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignMessageRequest,
) -> Result<SignMessageResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let sign_request = map_sign_message_request(request)?;
    let response = workflow
        .sign_message(sign_request)
        .await
        .map_err(HWCoreError::from)?;
    let normalized = normalize_message_signature(&response).map_err(HWCoreError::from)?;
    Ok(SignMessageResult {
        chain: response.chain,
        address: response.address,
        signature: response.signature,
        signature_formatted: normalized.value,
        signature_encoding: map_signature_encoding(normalized.encoding),
    })
}

async fn sign_typed_data_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTypedDataRequest,
) -> Result<SignTypedDataResult, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    let sign_request = map_sign_typed_data_request(request)?;
    let response = workflow
        .sign_typed_data(sign_request)
        .await
        .map_err(HWCoreError::from)?;
    let normalized = normalize_typed_data_signature(&response).map_err(HWCoreError::from)?;
    Ok(SignTypedDataResult {
        chain: response.chain,
        address: response.address,
        signature: response.signature,
        signature_formatted: normalized,
        signature_encoding: SignatureEncoding::Hex,
    })
}

#[derive(uniffi::Object)]
pub struct BleManagerHandle {
    manager: BleManager,
}

#[uniffi::export(async_runtime = "tokio")]
impl BleManagerHandle {
    #[uniffi::constructor]
    pub async fn new() -> Result<Self, HWCoreError> {
        let manager = BleManager::new().await.map_err(HWCoreError::from)?;
        Ok(Self { manager })
    }

    #[uniffi::method]
    pub async fn discover_trezor(
        &self,
        duration_ms: u64,
    ) -> Result<Vec<Arc<BleDiscoveredDevice>>, HWCoreError> {
        let (profile, devices) = scan_trezor(&self.manager, Duration::from_millis(duration_ms))
            .await
            .map_err(HWCoreError::from)?;
        Ok(devices
            .into_iter()
            .map(|device| Arc::new(BleDiscoveredDevice::new(device, profile)))
            .collect())
    }
}

#[derive(uniffi::Object)]
pub struct BleDiscoveredDevice {
    device: Mutex<Option<DiscoveredDevice>>,
    info: DeviceInfo,
    profile: BleProfile,
}

impl BleDiscoveredDevice {
    pub(crate) fn new(device: DiscoveredDevice, profile: BleProfile) -> Self {
        let info = device.info().clone();
        Self {
            device: Mutex::new(Some(device)),
            info,
            profile,
        }
    }

    fn take_device(&self) -> Result<DiscoveredDevice, HWCoreError> {
        let mut slot = self.device.lock();
        slot.take()
            .ok_or_else(|| HWCoreError::Validation("device already connected".to_string()))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl BleDiscoveredDevice {
    pub fn info(&self) -> BleDeviceInfo {
        self.info.clone()
    }

    #[uniffi::method]
    pub async fn connect(&self) -> Result<Arc<BleSessionHandle>, HWCoreError> {
        let device = self.take_device()?;
        let info = device.info().clone();
        let session = connect_trezor_device(device, self.profile)
            .await
            .map_err(HWCoreError::from)?;

        Ok(Arc::new(BleSessionHandle::new(session, info)))
    }

    #[uniffi::method]
    pub async fn connect_ready_workflow(
        &self,
        config: HostConfig,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        self.connect_ready_workflow_with_policy(config, None, try_to_unlock, None)
            .await
    }

    #[uniffi::method]
    pub async fn connect_ready_workflow_with_storage(
        &self,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        self.connect_ready_workflow_with_policy(config, storage_path, try_to_unlock, None)
            .await
    }

    #[uniffi::method]
    pub async fn connect_ready_workflow_with_policy(
        &self,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
        retry_policy: Option<SessionRetryPolicy>,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let device = self.take_device()?;
        let storage = storage_path.map(storage_from_path).transpose()?;
        let workflow = connect_and_bootstrap_session(
            device,
            self.profile,
            config.into(),
            storage,
            bootstrap_options(try_to_unlock, retry_policy),
        )
        .await
        .map_err(HWCoreError::from)?;

        let handle = Arc::new(BleWorkflowHandle::new(workflow));
        *handle.session_ready.lock().await = true;
        handle
            .push_event(WorkflowEvent {
                kind: WorkflowEventKind::Ready,
                code: "SESSION_READY".to_string(),
                message: "BLE workflow is authenticated and session-ready".to_string(),
            })
            .await;
        Ok(handle)
    }
}

#[derive(uniffi::Object)]
pub struct BleSessionHandle {
    session: AsyncMutex<Option<BleSession>>,
    info: DeviceInfo,
}

impl BleSessionHandle {
    pub(crate) fn new(session: BleSession, info: DeviceInfo) -> Self {
        Self {
            session: AsyncMutex::new(Some(session)),
            info,
        }
    }

    async fn take_session(&self) -> Result<BleSession, HWCoreError> {
        let mut guard = self.session.lock().await;
        guard
            .take()
            .ok_or_else(|| HWCoreError::message("BLE session already consumed"))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl BleSessionHandle {
    #[uniffi::method]
    pub fn device_info(&self) -> BleDeviceInfo {
        self.info.clone()
    }

    #[uniffi::method]
    pub async fn into_workflow(
        self: Arc<Self>,
        config: HostConfig,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        self.into_workflow_with_storage(config, None).await
    }

    #[uniffi::method]
    pub async fn into_workflow_with_storage(
        self: Arc<Self>,
        config: HostConfig,
        storage_path: Option<String>,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let session = self.take_session().await?;
        let backend = backend_from_session(session, DEFAULT_THP_TIMEOUT);
        let workflow = if let Some(path) = storage_path {
            let storage = storage_from_path(path)?;
            workflow_with_storage(backend, config.into(), storage).await?
        } else {
            new_workflow(backend, config.into())
        };
        Ok(Arc::new(BleWorkflowHandle::new(workflow)))
    }

    #[uniffi::method]
    pub async fn into_ready_workflow(
        self: Arc<Self>,
        config: HostConfig,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        self.into_ready_workflow_with_policy(config, None, try_to_unlock, None)
            .await
    }

    #[uniffi::method]
    pub async fn into_ready_workflow_with_storage(
        self: Arc<Self>,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        self.into_ready_workflow_with_policy(config, storage_path, try_to_unlock, None)
            .await
    }

    #[uniffi::method]
    pub async fn into_ready_workflow_with_policy(
        self: Arc<Self>,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
        retry_policy: Option<SessionRetryPolicy>,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let session = self.take_session().await?;
        let backend = backend_from_session(session, DEFAULT_THP_TIMEOUT);
        let workflow = if let Some(path) = storage_path {
            let storage = storage_from_path(path)?;
            workflow_with_storage(backend, config.into(), storage).await?
        } else {
            new_workflow(backend, config.into())
        };
        let handle = Arc::new(BleWorkflowHandle::new(workflow));
        handle
            .prepare_ready_session_with_policy(try_to_unlock, retry_policy)
            .await?;
        Ok(handle)
    }
}

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
    session_ready: AsyncMutex<bool>,
    events: AsyncMutex<VecDeque<WorkflowEvent>>,
    notify: Notify,
}

impl BleWorkflowHandle {
    pub(crate) fn new(workflow: ThpWorkflow<BleBackend>) -> Self {
        Self {
            workflow: AsyncMutex::new(workflow),
            session_ready: AsyncMutex::new(false),
            events: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    async fn push_event(&self, event: WorkflowEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        self.notify.notify_waiters();
    }

    async fn push_error_event(&self, error: &HWCoreError) {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Error,
            code: error.code().to_string(),
            message: error.detail().to_string(),
        })
        .await;
    }
}

#[cfg(test)]
mod tests;

mod workflow_api;
