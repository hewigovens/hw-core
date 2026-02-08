use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use hw_wallet::ble::{
    ReadyWorkflowOptions, backend_from_session, connect_and_prepare_workflow,
    connect_trezor_device, prepare_ready_workflow, scan_trezor, workflow as new_workflow,
};
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::timeout;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::Phase;
use trezor_connect::thp::ThpWorkflow;

use crate::errors::HWCoreError;
use crate::types::{
    HWBleDeviceInfo, HWHandshakeCache, HWHostConfig, HWThpState, HWWorkflowEvent,
    HWWorkflowEventKind,
};

const DEFAULT_THP_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(uniffi::Object)]
pub struct BleManagerHandle {
    manager: BleManager,
}

#[uniffi::export]
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

#[uniffi::export]
impl BleDiscoveredDevice {
    pub fn info(&self) -> HWBleDeviceInfo {
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
        config: HWHostConfig,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let device = self.take_device()?;
        let workflow = connect_and_prepare_workflow(
            device,
            self.profile,
            config,
            None,
            ReadyWorkflowOptions {
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
        handle
            .push_event(HWWorkflowEvent {
                kind: HWWorkflowEventKind::Ready,
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

#[uniffi::export]
impl BleSessionHandle {
    #[uniffi::method]
    pub fn device_info(&self) -> HWBleDeviceInfo {
        self.info.clone()
    }

    #[uniffi::method]
    pub async fn into_workflow(
        self: Arc<Self>,
        config: HWHostConfig,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let session = self.take_session().await?;
        let backend = backend_from_session(session, DEFAULT_THP_TIMEOUT);
        let workflow = new_workflow(backend, config);
        Ok(Arc::new(BleWorkflowHandle::new(workflow)))
    }

    #[uniffi::method]
    pub async fn into_ready_workflow(
        self: Arc<Self>,
        config: HWHostConfig,
        try_to_unlock: bool,
    ) -> Result<Arc<BleWorkflowHandle>, HWCoreError> {
        let session = self.take_session().await?;
        let backend = backend_from_session(session, DEFAULT_THP_TIMEOUT);
        let workflow = new_workflow(backend, config);
        let handle = Arc::new(BleWorkflowHandle::new(workflow));
        handle.prepare_ready_session(try_to_unlock).await?;
        Ok(handle)
    }
}

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
    events: AsyncMutex<VecDeque<HWWorkflowEvent>>,
    notify: Notify,
}

impl BleWorkflowHandle {
    pub(crate) fn new(workflow: ThpWorkflow<BleBackend>) -> Self {
        Self {
            workflow: AsyncMutex::new(workflow),
            events: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    async fn push_event(&self, event: HWWorkflowEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        self.notify.notify_waiters();
    }

    async fn push_error_event(&self, error: &HWCoreError) {
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Error,
            code: error.code().to_string(),
            message: error.detail().to_string(),
        })
        .await;
    }
}

#[uniffi::export]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn create_channel(&self) -> Result<HWHandshakeCache, HWCoreError> {
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
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
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
            code: "CREATE_CHANNEL_OK".to_string(),
            message: "THP channel created".to_string(),
        })
        .await;
        Ok(cache)
    }

    #[uniffi::method]
    pub async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
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
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
            code: "HANDSHAKE_OK".to_string(),
            message: "THP handshake complete".to_string(),
        })
        .await;
        if matches!(state, Phase::Pairing) && !is_paired {
            self.push_event(HWWorkflowEvent {
                kind: HWWorkflowEventKind::PairingPrompt,
                code: "PAIRING_REQUIRED".to_string(),
                message: "Pairing interaction is required (code-entry expected)".to_string(),
            })
            .await;
        }
        Ok(())
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
            code: "CREATE_SESSION_START".to_string(),
            message: "Creating wallet session".to_string(),
        })
        .await;
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::ButtonRequest,
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
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Ready,
            code: "SESSION_READY".to_string(),
            message: "Wallet session created".to_string(),
        })
        .await;
        Ok(())
    }

    #[uniffi::method]
    pub async fn prepare_ready_session(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Progress,
            code: "PREPARE_READY_START".to_string(),
            message: "Preparing authenticated wallet session".to_string(),
        })
        .await;
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during handshake/session setup".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let options = ReadyWorkflowOptions {
            thp_timeout: DEFAULT_THP_TIMEOUT,
            try_to_unlock,
            passphrase: None,
            on_device: false,
            derive_cardano: false,
        };
        if let Err(err) = prepare_ready_workflow(&mut workflow, &options).await {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        drop(workflow);
        self.push_event(HWWorkflowEvent {
            kind: HWWorkflowEventKind::Ready,
            code: "SESSION_READY".to_string(),
            message: "BLE workflow is authenticated and session-ready".to_string(),
        })
        .await;
        Ok(())
    }

    #[uniffi::method]
    pub async fn abort(&self) -> Result<(), HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow.abort().await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn state(&self) -> HWThpState {
        let workflow = self.workflow.lock().await;
        HWThpState::from(workflow.state())
    }

    #[uniffi::method]
    pub async fn host_config(&self) -> HWHostConfig {
        let workflow = self.workflow.lock().await;
        workflow.host_config().clone()
    }

    #[uniffi::method]
    pub async fn next_event(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<Option<HWWorkflowEvent>, HWCoreError> {
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
