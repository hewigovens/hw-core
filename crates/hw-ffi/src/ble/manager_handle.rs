use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile};

use super::BleDiscoveredDevice;
use crate::errors::HWCoreError;
use crate::platform::init_platform_tracing_once;

#[derive(uniffi::Object)]
pub struct BleManagerHandle {
    manager: BleManager,
}

#[uniffi::export(async_runtime = "tokio")]
impl BleManagerHandle {
    #[uniffi::constructor]
    pub async fn create() -> Result<Self, HWCoreError> {
        init_platform_tracing_once();
        let manager = BleManager::new().await?;
        Ok(Self { manager })
    }

    #[uniffi::method]
    pub async fn discover_trezor(
        &self,
        duration_ms: u64,
    ) -> Result<Vec<Arc<BleDiscoveredDevice>>, HWCoreError> {
        let profile = BleProfile::TREZOR_SAFE7;
        let devices = self
            .manager
            .scan_profile(profile, Duration::from_millis(duration_ms))
            .await?;
        Ok(devices
            .into_iter()
            .map(|device| Arc::new(BleDiscoveredDevice::new(device, profile)))
            .collect())
    }
}
