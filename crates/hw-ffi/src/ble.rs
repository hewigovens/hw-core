use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use hw_wallet::ble::{
    SessionPhase as WalletSessionPhase, backend_from_session, connect_and_bootstrap_session,
    connect_trezor_device, scan_trezor, session_phase, session_state as build_session_state,
    workflow as new_workflow, workflow_with_storage,
};
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{Phase, ThpWorkflow};

use crate::errors::HWCoreError;
use crate::types::{
    AddressResult, BleDeviceInfo, GetAddressRequest, HandshakeCache, HostConfig, PairingProgress,
    PairingPrompt, SessionHandshakeState, SessionRetryPolicy, SessionState, SignMessageRequest,
    SignMessageResult, SignTxRequest, SignTxResult, SignTypedDataRequest, SignTypedDataResult,
    ThpState, WorkflowEvent, WorkflowEventKind,
};

pub(crate) const MIN_SOLANA_SERIALIZED_TX_BYTES: usize = 16;

mod pairing;
mod request_mapping;
mod session;
mod workflow_ops;

pub(crate) use pairing::{
    pairing_confirm_connection_for_workflow, pairing_start_for_state,
    pairing_submit_code_for_workflow,
};
pub(crate) use session::{DEFAULT_THP_TIMEOUT, bootstrap_options, storage_from_path};
pub(crate) use workflow_ops::{
    get_address_for_workflow, get_nonce_for_workflow, sign_message_for_workflow,
    sign_tx_for_workflow, sign_typed_data_for_workflow,
};

#[derive(uniffi::Object)]
pub struct BleManagerHandle {
    manager: BleManager,
}

#[uniffi::export(async_runtime = "tokio")]
impl BleManagerHandle {
    #[uniffi::constructor]
    pub async fn new() -> Result<Self, HWCoreError> {
        crate::init_platform_tracing_once();
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
