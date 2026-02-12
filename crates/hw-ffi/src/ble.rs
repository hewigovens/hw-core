use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ble::{
    SessionBootstrapOptions, SessionPhase as WalletSessionPhase, advance_to_paired,
    advance_to_ready, backend_from_session, connect_and_prepare_workflow, connect_trezor_device,
    scan_trezor, session_phase, session_state as build_session_state, workflow as new_workflow,
    workflow_with_storage,
};
use hw_wallet::eth::{TxAccessListInput, TxInput, build_sign_tx_request, verify_sign_tx_response};
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::timeout;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::types::PairingPrompt as ThpPairingPrompt;
use trezor_connect::thp::{
    FileStorage, GetAddressRequest as ThpGetAddressRequest, PairingController, PairingDecision,
    PairingMethod as ThpPairingMethod, Phase, ThpWorkflow, ThpWorkflowError,
};

use crate::errors::HWCoreError;
use crate::types::{
    AccessListEntry, AddressResult, BleDeviceInfo, GetAddressRequest, HandshakeCache, HostConfig,
    PairingProgress, PairingProgressKind, PairingPrompt, SessionHandshakeState, SessionState,
    SignTxRequest, SignTxResult, ThpState, WorkflowEvent, WorkflowEventKind,
};

const DEFAULT_THP_TIMEOUT: Duration = Duration::from_secs(60);

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
    })
}

fn map_sign_tx_request(
    request: SignTxRequest,
) -> Result<trezor_connect::thp::SignTxRequest, HWCoreError> {
    if request.chain != crate::types::Chain::Ethereum {
        return Err(HWCoreError::Validation(
            "sign_tx currently supports only Ethereum".to_string(),
        ));
    }

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
        self.connect_ready_workflow_with_storage(config, None, try_to_unlock)
            .await
    }

    #[uniffi::method]
    pub async fn connect_ready_workflow_with_storage(
        &self,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let device = self.take_device()?;
        let storage = storage_path.map(storage_from_path).transpose()?;
        let workflow = connect_and_prepare_workflow(
            device,
            self.profile,
            config.into(),
            storage,
            SessionBootstrapOptions {
                thp_timeout: DEFAULT_THP_TIMEOUT,
                try_to_unlock,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
            },
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
        self.into_ready_workflow_with_storage(config, None, try_to_unlock)
            .await
    }

    #[uniffi::method]
    pub async fn into_ready_workflow_with_storage(
        self: Arc<Self>,
        config: HostConfig,
        storage_path: Option<String>,
        try_to_unlock: bool,
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
        handle.prepare_ready_session(try_to_unlock).await?;
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
mod tests {
    use std::collections::VecDeque;

    use super::{
        get_address_for_workflow, pairing_confirm_connection_for_workflow, pairing_start_for_state,
        pairing_submit_code_for_workflow, sign_tx_for_workflow,
    };
    use trezor_connect::thp::backend::{BackendError, BackendResult, ThpBackend};
    use trezor_connect::thp::types::{
        CodeEntryChallengeRequest, CodeEntryChallengeResponse, CreateChannelRequest,
        CreateChannelResponse, CreateSessionRequest, CreateSessionResponse, CredentialRequest,
        CredentialResponse, GetAddressResponse, HandshakeCompletionRequest,
        HandshakeCompletionResponse, HandshakeCompletionState, HandshakeInitOutcome,
        HandshakeInitRequest, KnownCredential, PairingRequest, PairingRequestApproved,
        PairingTagRequest, PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
        SignTxRequest, SignTxResponse, ThpProperties,
    };
    use trezor_connect::thp::{Chain, HostConfig, PairingMethod, Phase, ThpWorkflow};

    use crate::types::{GetAddressRequest, SignTxRequest as FfiSignTxRequest};

    struct MockBackend {
        handshake_hash: Vec<u8>,
        completion_state: HandshakeCompletionState,
        confirmed_connection: bool,
        expected_code: Option<String>,
        select_responses: VecDeque<SelectMethodResponse>,
        last_get_address_request: Option<trezor_connect::thp::GetAddressRequest>,
        last_sign_tx_request: Option<SignTxRequest>,
    }

    impl MockBackend {
        fn paired_requires_confirmation() -> Self {
            Self {
                handshake_hash: b"paired-handshake".to_vec(),
                completion_state: HandshakeCompletionState::Paired,
                confirmed_connection: false,
                expected_code: None,
                select_responses: VecDeque::new(),
                last_get_address_request: None,
                last_sign_tx_request: None,
            }
        }

        fn requires_code_entry_pairing() -> Self {
            let mut select_responses = VecDeque::new();
            select_responses.push_back(SelectMethodResponse::CodeEntryCommitment {
                commitment: vec![0xAB; 32],
            });
            Self {
                handshake_hash: b"code-entry-handshake".to_vec(),
                completion_state: HandshakeCompletionState::RequiresPairing,
                confirmed_connection: false,
                expected_code: Some("123456".to_string()),
                select_responses,
                last_get_address_request: None,
                last_sign_tx_request: None,
            }
        }
    }

    impl ThpBackend for MockBackend {
        async fn create_channel(
            &mut self,
            request: CreateChannelRequest,
        ) -> BackendResult<CreateChannelResponse> {
            Ok(CreateChannelResponse {
                nonce: request.nonce,
                channel: 0xBEEF,
                handshake_hash: self.handshake_hash.clone(),
                properties: ThpProperties {
                    internal_model: "T3W1".into(),
                    model_variant: 1,
                    protocol_version_major: 2,
                    protocol_version_minor: 0,
                    pairing_methods: vec![PairingMethod::CodeEntry],
                },
            })
        }

        async fn handshake_init(
            &mut self,
            _request: HandshakeInitRequest,
        ) -> BackendResult<HandshakeInitOutcome> {
            Ok(HandshakeInitOutcome {
                host_encrypted_static_pubkey: vec![1, 2, 3],
                encrypted_payload: vec![4, 5, 6],
                trezor_encrypted_static_pubkey: vec![7, 8, 9],
                handshake_hash: self.handshake_hash.clone(),
                host_key: vec![0x11; 32],
                trezor_key: vec![0x22; 32],
                host_static_key: vec![0x33; 32],
                host_static_public_key: vec![0x44; 32],
                pairing_methods: vec![PairingMethod::CodeEntry],
                credentials: vec![KnownCredential {
                    credential: "cred".into(),
                    trezor_static_public_key: Some(vec![0x55; 32]),
                    autoconnect: false,
                }],
                selected_credential: Some(KnownCredential {
                    credential: "cred".into(),
                    trezor_static_public_key: Some(vec![0x55; 32]),
                    autoconnect: false,
                }),
                nfc_data: None,
                handshake_commitment: None,
                trezor_cpace_public_key: None,
                code_entry_challenge: None,
            })
        }

        async fn handshake_complete(
            &mut self,
            _request: HandshakeCompletionRequest,
        ) -> BackendResult<HandshakeCompletionResponse> {
            Ok(HandshakeCompletionResponse {
                state: self.completion_state,
            })
        }

        async fn pairing_request(
            &mut self,
            _request: PairingRequest,
        ) -> BackendResult<PairingRequestApproved> {
            Ok(PairingRequestApproved)
        }

        async fn select_pairing_method(
            &mut self,
            _request: SelectMethodRequest,
        ) -> BackendResult<SelectMethodResponse> {
            self.select_responses
                .pop_front()
                .ok_or_else(|| BackendError::Transport("unexpected select_pairing_method".into()))
        }

        async fn code_entry_challenge(
            &mut self,
            _request: CodeEntryChallengeRequest,
        ) -> BackendResult<CodeEntryChallengeResponse> {
            Ok(CodeEntryChallengeResponse {
                trezor_cpace_public_key: vec![0xCD; 32],
            })
        }

        async fn send_pairing_tag(
            &mut self,
            request: PairingTagRequest,
        ) -> BackendResult<PairingTagResponse> {
            match request {
                PairingTagRequest::CodeEntry { code, .. } => {
                    if self.expected_code.as_deref() == Some(code.as_str()) {
                        Ok(PairingTagResponse::Accepted {
                            secret: vec![0xEF; 32],
                        })
                    } else {
                        Ok(PairingTagResponse::Retry("invalid code".into()))
                    }
                }
                _ => Err(BackendError::UnsupportedPairingMethod),
            }
        }

        async fn credential_request(
            &mut self,
            _request: CredentialRequest,
        ) -> BackendResult<CredentialResponse> {
            self.confirmed_connection = true;
            Ok(CredentialResponse {
                trezor_static_public_key: vec![0x66; 32],
                credential: "cred".into(),
                autoconnect: false,
            })
        }

        async fn end_request(&mut self) -> BackendResult<()> {
            Ok(())
        }

        async fn create_new_session(
            &mut self,
            _request: CreateSessionRequest,
        ) -> BackendResult<CreateSessionResponse> {
            if self.completion_state == HandshakeCompletionState::Paired
                && !self.confirmed_connection
            {
                return Err(BackendError::Device(
                    "session requires connection confirmation".into(),
                ));
            }
            Ok(CreateSessionResponse)
        }

        async fn get_address(
            &mut self,
            request: trezor_connect::thp::GetAddressRequest,
        ) -> BackendResult<GetAddressResponse> {
            self.last_get_address_request = Some(request);
            Ok(GetAddressResponse {
                chain: Chain::Ethereum,
                address: "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE".into(),
                mac: Some(vec![0xAA; 32]),
                public_key: Some("xpub-test".into()),
            })
        }

        async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
            self.last_sign_tx_request = Some(request);
            Ok(SignTxResponse {
                chain: Chain::Ethereum,
                v: 0,
                r: vec![0xAA; 32],
                s: vec![0xBB; 32],
            })
        }

        async fn abort(&mut self) -> BackendResult<()> {
            Ok(())
        }
    }

    fn default_host_config() -> HostConfig {
        let mut config = HostConfig::new("test-host", "hw-core/ffi");
        config.pairing_methods = vec![PairingMethod::CodeEntry];
        config
    }

    #[tokio::test]
    async fn paired_handshake_requires_connection_confirmation_before_session() {
        let backend = MockBackend::paired_requires_confirmation();
        let mut workflow = ThpWorkflow::new(backend, default_host_config());

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();
        assert_eq!(workflow.state().phase(), Phase::Pairing);
        assert!(workflow.state().is_paired());

        let err = workflow
            .create_session(None, false, false)
            .await
            .expect_err("session should fail before confirmation");
        assert!(
            err.to_string().contains("connection confirmation"),
            "unexpected error: {err}"
        );

        let progress = pairing_confirm_connection_for_workflow(&mut workflow)
            .await
            .expect("confirmation succeeds");
        assert_eq!(progress.kind, crate::types::PairingProgressKind::Completed);

        workflow
            .create_session(None, false, false)
            .await
            .expect("session succeeds after confirmation");
    }

    #[tokio::test]
    async fn code_entry_pairing_submit_completes_pairing() {
        let backend = MockBackend::requires_code_entry_pairing();
        let mut workflow = ThpWorkflow::new(backend, default_host_config());

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();
        assert_eq!(workflow.state().phase(), Phase::Pairing);
        assert!(!workflow.state().is_paired());

        let prompt = pairing_start_for_state(workflow.state()).expect("pairing prompt");
        assert!(!prompt.requires_connection_confirmation);
        assert!(prompt.available_methods.contains(&PairingMethod::CodeEntry));

        pairing_submit_code_for_workflow(&mut workflow, "123456".into())
            .await
            .expect("pairing completes");
        assert_eq!(workflow.state().phase(), Phase::Paired);
    }

    #[tokio::test]
    async fn typed_address_and_sign_requests_map_to_workflow_calls() {
        let backend = MockBackend::paired_requires_confirmation();
        let mut workflow = ThpWorkflow::new(backend, default_host_config());

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();
        pairing_confirm_connection_for_workflow(&mut workflow)
            .await
            .unwrap();
        workflow.create_session(None, false, false).await.unwrap();

        let address = get_address_for_workflow(
            &mut workflow,
            GetAddressRequest {
                chain: Chain::Ethereum,
                path: "m/44'/60'/0'/0/0".into(),
                show_on_device: true,
                include_public_key: true,
                chunkify: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            address.address,
            "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE"
        );

        let signed = sign_tx_for_workflow(
            &mut workflow,
            FfiSignTxRequest {
                chain: Chain::Ethereum,
                path: "m/44'/60'/0'/0/0".into(),
                to: "0x000000000000000000000000000000000000dead".into(),
                value: "0x0".into(),
                nonce: "0x0".into(),
                gas_limit: "0x5208".into(),
                chain_id: 1,
                data: "0x".into(),
                max_fee_per_gas: "0x3b9aca00".into(),
                max_priority_fee: "0x59682f00".into(),
                access_list: Vec::new(),
                chunkify: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(signed.chain, Chain::Ethereum);
        assert_eq!(signed.v, 0);
        assert_eq!(signed.r.len(), 32);
        assert_eq!(signed.s.len(), 32);

        let backend = workflow.backend_mut();
        let get_address_request = backend.last_get_address_request.as_ref().unwrap();
        assert_eq!(get_address_request.chain, Chain::Ethereum);
        assert!(get_address_request.show_display);
        assert!(get_address_request.include_public_key);
        assert!(get_address_request.chunkify);

        let sign_request = backend.last_sign_tx_request.as_ref().unwrap();
        assert_eq!(sign_request.chain, Chain::Ethereum);
        assert_eq!(sign_request.chain_id, 1);
        assert_eq!(
            sign_request.path,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
        );
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn session_state(&self) -> Result<SessionState, HWCoreError> {
        let ready = *self.session_ready.lock().await;
        let workflow = self.workflow.lock().await;
        let phase = session_phase(workflow.state(), ready);
        let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
            Some(pairing_start_for_state(workflow.state())?.message)
        } else {
            None
        };
        Ok(build_session_state(phase, prompt_message))
    }

    #[uniffi::method]
    pub async fn pair_only(&self, try_to_unlock: bool) -> Result<SessionState, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIR_ONLY_START".to_string(),
            message: "Advancing workflow to paired state".to_string(),
        })
        .await;

        let mut workflow = self.workflow.lock().await;
        let result = advance_to_paired(&mut workflow, try_to_unlock).await;
        let mapped = match result {
            Ok(phase) => {
                let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
                    Some(pairing_start_for_state(workflow.state())?.message)
                } else {
                    None
                };
                Ok(build_session_state(phase, prompt_message))
            }
            Err(err) => Err(HWCoreError::from(err)),
        };
        drop(workflow);

        *self.session_ready.lock().await = false;

        match mapped {
            Ok(state) => {
                if matches!(state.phase, WalletSessionPhase::NeedsPairingCode)
                    && let Some(message) = &state.prompt_message
                {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::PairingPrompt,
                        code: "PAIRING_CODE_REQUIRED".to_string(),
                        message: message.clone(),
                    })
                    .await;
                }
                Ok(state)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn connect_ready(&self, try_to_unlock: bool) -> Result<SessionState, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CONNECT_READY_START".to_string(),
            message: "Advancing workflow to session-ready state".to_string(),
        })
        .await;

        let mut ready = *self.session_ready.lock().await;
        let options = SessionBootstrapOptions {
            thp_timeout: DEFAULT_THP_TIMEOUT,
            try_to_unlock,
            passphrase: None,
            on_device: false,
            derive_cardano: false,
        };

        let mut workflow = self.workflow.lock().await;
        let result = advance_to_ready(&mut workflow, &mut ready, &options).await;
        let mapped = match result {
            Ok(phase) => {
                let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
                    Some(pairing_start_for_state(workflow.state())?.message)
                } else {
                    None
                };
                Ok(build_session_state(phase, prompt_message))
            }
            Err(err) => Err(HWCoreError::from(err)),
        };
        drop(workflow);

        *self.session_ready.lock().await = ready;

        match mapped {
            Ok(state) => {
                if matches!(state.phase, WalletSessionPhase::Ready) {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::Ready,
                        code: "SESSION_READY".to_string(),
                        message: "BLE workflow is authenticated and session-ready".to_string(),
                    })
                    .await;
                } else if matches!(state.phase, WalletSessionPhase::NeedsPairingCode)
                    && let Some(message) = &state.prompt_message
                {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::PairingPrompt,
                        code: "PAIRING_CODE_REQUIRED".to_string(),
                        message: message.clone(),
                    })
                    .await;
                }
                Ok(state)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn create_channel(&self) -> Result<HandshakeCache, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_CHANNEL_START".to_string(),
            message: "Creating THP channel".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow.create_channel().await {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let cache = workflow.state().handshake_cache().cloned().ok_or_else(|| {
            HWCoreError::Workflow("handshake cache missing after create_channel".to_string())
        })?;
        drop(workflow);
        *self.session_ready.lock().await = false;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_CHANNEL_OK".to_string(),
            message: "THP channel created".to_string(),
        })
        .await;
        Ok(cache)
    }

    #[uniffi::method]
    pub async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "HANDSHAKE_START".to_string(),
            message: "Performing THP handshake".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow.handshake(try_to_unlock).await {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let state = workflow.state().phase();
        let is_paired = workflow.state().is_paired();
        drop(workflow);
        *self.session_ready.lock().await = false;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "HANDSHAKE_OK".to_string(),
            message: "THP handshake complete".to_string(),
        })
        .await;
        if matches!(state, Phase::Pairing) && !is_paired {
            self.push_event(WorkflowEvent {
                kind: WorkflowEventKind::PairingPrompt,
                code: "PAIRING_REQUIRED".to_string(),
                message: "Pairing interaction is required (code-entry expected)".to_string(),
            })
            .await;
        }
        Ok(())
    }

    #[uniffi::method]
    pub async fn prepare_channel_and_handshake(
        &self,
        try_to_unlock: bool,
    ) -> Result<SessionHandshakeState, HWCoreError> {
        self.create_channel().await?;
        self.handshake(try_to_unlock).await?;

        let state = self.state().await;
        match state.phase {
            Phase::Paired => Ok(SessionHandshakeState::Ready),
            Phase::Pairing => {
                let prompt = self.pairing_start().await?;
                if prompt.requires_connection_confirmation {
                    Ok(SessionHandshakeState::ConnectionConfirmationRequired { prompt })
                } else {
                    Ok(SessionHandshakeState::PairingRequired { prompt })
                }
            }
            Phase::Handshake => Err(HWCoreError::Workflow(
                "unexpected handshake phase".to_string(),
            )),
        }
    }

    #[uniffi::method]
    pub async fn pairing_start(&self) -> Result<PairingPrompt, HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        if workflow.state().phase() == Phase::Pairing
            && !workflow.state().is_paired()
            && let Err(err) = workflow.pairing(None).await
            && !matches!(err, ThpWorkflowError::PairingInteractionRequired)
        {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let prompt = pairing_start_for_state(workflow.state())?;
        drop(workflow);

        let code = if prompt.requires_connection_confirmation {
            "PAIRING_CONFIRMATION_REQUIRED"
        } else {
            "PAIRING_CODE_REQUIRED"
        };
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::PairingPrompt,
            code: code.to_string(),
            message: prompt.message.clone(),
        })
        .await;
        Ok(prompt)
    }

    #[uniffi::method]
    pub async fn pairing_submit_code(&self, code: String) -> Result<PairingProgress, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIRING_SUBMIT_CODE_START".to_string(),
            message: "Submitting pairing code".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = pairing_submit_code_for_workflow(&mut workflow, code).await;
        drop(workflow);

        match result {
            Ok(progress) => {
                *self.session_ready.lock().await = false;
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "PAIRING_COMPLETE".to_string(),
                    message: progress.message.clone(),
                })
                .await;
                Ok(progress)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn pairing_confirm_connection(&self) -> Result<PairingProgress, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIRING_CONFIRM_CONNECTION_START".to_string(),
            message: "Confirming paired connection with device".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = pairing_confirm_connection_for_workflow(&mut workflow).await;
        drop(workflow);

        match result {
            Ok(progress) => {
                *self.session_ready.lock().await = false;
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "PAIRING_CONFIRM_CONNECTION_OK".to_string(),
                    message: progress.message.clone(),
                })
                .await;
                Ok(progress)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_SESSION_START".to_string(),
            message: "Creating wallet session".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during session creation".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow
            .create_session(passphrase, on_device, derive_cardano)
            .await
        {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        drop(workflow);
        *self.session_ready.lock().await = true;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Ready,
            code: "SESSION_READY".to_string(),
            message: "Wallet session created".to_string(),
        })
        .await;
        Ok(())
    }

    #[uniffi::method]
    pub async fn prepare_ready_session(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        match self.connect_ready(try_to_unlock).await? {
            SessionState {
                phase: WalletSessionPhase::Ready,
                ..
            } => Ok(()),
            SessionState {
                phase: WalletSessionPhase::NeedsPairingCode,
                ..
            } => Err(HWCoreError::Workflow(
                "pairing interaction required before session can be prepared".to_string(),
            )),
            state => Err(HWCoreError::Workflow(format!(
                "unexpected workflow step after connect_ready: {:?}",
                state.phase
            ))),
        }
    }

    #[uniffi::method]
    pub async fn get_address(
        &self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "GET_ADDRESS_START".to_string(),
            message: "Requesting address from device".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = get_address_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "GET_ADDRESS_OK".to_string(),
                    message: "Address received".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn sign_tx(&self, request: SignTxRequest) -> Result<SignTxResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "SIGN_TX_START".to_string(),
            message: "Requesting transaction signature from device".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during signing".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = sign_tx_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "SIGN_TX_OK".to_string(),
                    message: "Transaction signed".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn abort(&self) -> Result<(), HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow.abort().await?;
        drop(workflow);
        *self.session_ready.lock().await = false;
        Ok(())
    }

    #[uniffi::method]
    pub async fn state(&self) -> ThpState {
        let workflow = self.workflow.lock().await;
        ThpState::from(workflow.state())
    }

    #[uniffi::method]
    pub async fn host_config(&self) -> HostConfig {
        let workflow = self.workflow.lock().await;
        workflow.host_config().clone().into()
    }

    #[uniffi::method]
    pub async fn next_event(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<Option<WorkflowEvent>, HWCoreError> {
        loop {
            let maybe_event = {
                let mut events = self.events.lock().await;
                events.pop_front()
            };
            if maybe_event.is_some() {
                return Ok(maybe_event);
            }

            let notified = self.notify.notified();
            if let Some(timeout_ms) = timeout_ms {
                if timeout(Duration::from_millis(timeout_ms), notified)
                    .await
                    .is_err()
                {
                    return Ok(None);
                }
            } else {
                notified.await;
            }
        }
    }
}
