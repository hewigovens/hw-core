use super::{LedgerModel, LedgerSessionHandle};
use crate::{BleDeviceInfo, HWCoreError};
use ble_transport::{DeviceInfo, DiscoveredDevice};
use ledger_connect::{LedgerBleTransport, LedgerClient};
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

#[derive(uniffi::Object)]
pub struct LedgerDiscoveredDevice {
    device: Mutex<Option<DiscoveredDevice>>,
    info: DeviceInfo,
    model: LedgerModel,
}

impl LedgerDiscoveredDevice {
    pub(crate) fn new(device: DiscoveredDevice, model: LedgerModel) -> Self {
        let info = device.info().clone();
        Self {
            device: Mutex::new(Some(device)),
            info,
            model,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl LedgerDiscoveredDevice {
    pub fn info(&self) -> BleDeviceInfo {
        self.info.clone()
    }

    /// Unlock the Ledger and open the app matching the requested chain.
    pub async fn connect(&self, timeout_ms: u64) -> Result<Arc<LedgerSessionHandle>, HWCoreError> {
        if timeout_ms == 0 {
            return Err(HWCoreError::Validation("timeout must be positive".into()));
        }
        let device =
            self.device.lock().take().ok_or_else(|| {
                HWCoreError::Validation("device already consumed; scan again".into())
            })?;
        let duration = Duration::from_millis(timeout_ms);
        let session = timeout(duration, device.connect(self.model.profile()))
            .await
            .map_err(|_| HWCoreError::Timeout("Ledger connection timed out".into()))??;
        let transport = LedgerBleTransport::new(session, duration).await?;
        Ok(Arc::new(LedgerSessionHandle::new(LedgerClient::new(
            transport,
        ))))
    }
}
