use std::sync::Arc;

use ble_transport::{BleProfile, DeviceInfo, DiscoveredDevice};
use hw_wallet::ble::{
    SessionBootstrapOptions, connect_and_bootstrap_session, connect_trezor_device,
};
use parking_lot::Mutex;
use trezor_connect::thp::FileStorage;

use super::bootstrap_options::SessionBootstrapOptionsExt;
use super::file_storage::FileStorageExt;
use super::{BleSessionHandle, BleWorkflowHandle};
use crate::errors::HWCoreError;
use crate::types::{BleDeviceInfo, HostConfig, SessionRetryPolicy};

#[derive(uniffi::Object)]
pub struct BleDiscoveredDevice {
    device: Mutex<Option<DiscoveredDevice>>,
    info: DeviceInfo,
    profile: BleProfile,
}

impl BleDiscoveredDevice {
    pub(super) fn new(device: DiscoveredDevice, profile: BleProfile) -> Self {
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
        let session = connect_trezor_device(device, self.profile).await?;
        Ok(Arc::new(BleSessionHandle::new(session)))
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
        let storage = storage_path
            .map(FileStorage::from_storage_path)
            .transpose()?;
        let workflow = connect_and_bootstrap_session(
            device,
            self.profile,
            config.into(),
            storage,
            SessionBootstrapOptions::from_ffi(try_to_unlock, retry_policy),
        )
        .await?;
        Ok(Arc::new(BleWorkflowHandle::ready(workflow).await))
    }
}
