use std::sync::{Arc, Mutex};
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use tokio::sync::Mutex as AsyncMutex;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::ThpWorkflow;

use crate::errors::HWCoreError;
use crate::types::{HWBleDeviceInfo, HWHandshakeCache, HWHostConfig, HWThpState};

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
        let profile = BleProfile::trezor_safe7()
            .ok_or_else(|| HWCoreError::message("BLE profile not built into this binary"))?;
        let devices = self
            .manager
            .scan_profile(profile, Duration::from_millis(duration_ms))
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
}

#[uniffi::export]
impl BleDiscoveredDevice {
    pub fn info(&self) -> HWBleDeviceInfo {
        self.info.clone()
    }

    #[uniffi::method]
    pub async fn connect(&self) -> Result<Arc<BleSessionHandle>, HWCoreError> {
        let (info, peripheral) = {
            let mut slot = self.device.lock().expect("poisoned mutex");
            let device = slot
                .take()
                .ok_or_else(|| HWCoreError::message("device already connected"))?;
            device.into_parts()
        };

        let session = BleSession::new(peripheral, self.profile, info.clone())
            .await
            .map_err(HWCoreError::from)?;

        Ok(Arc::new(BleSessionHandle::new(session, info)))
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
        let backend = BleBackend::from_session(session);
        let workflow = ThpWorkflow::new(backend, config);
        Ok(Arc::new(BleWorkflowHandle::new(workflow)))
    }
}

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
}

impl BleWorkflowHandle {
    pub(crate) fn new(workflow: ThpWorkflow<BleBackend>) -> Self {
        Self {
            workflow: AsyncMutex::new(workflow),
        }
    }
}

#[uniffi::export]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn create_channel(&self) -> Result<HWHandshakeCache, HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow.create_channel().await?;
        let cache = workflow
            .state()
            .handshake_cache()
            .ok_or_else(|| HWCoreError::message("handshake cache missing"))?;
        Ok(cache)
    }

    #[uniffi::method]
    pub async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow.handshake(try_to_unlock).await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow
            .create_session(passphrase, on_device, derive_cardano)
            .await?;
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
}
