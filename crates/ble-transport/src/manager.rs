use std::time::Duration;

use btleplug::api::{Central, Manager as _, ScanFilter};
use btleplug::platform::{Adapter, Manager};
use tokio::time;

use crate::{BleError, BleProfile, BleResult, DeviceInfo, DiscoveredDevice};

pub struct BleManager {
    adapter: Adapter,
}

impl BleManager {
    pub async fn new() -> BleResult<Self> {
        let manager = Manager::new().await?;
        let adapter = manager
            .adapters()
            .await?
            .into_iter()
            .next()
            .ok_or(BleError::AdapterUnavailable)?;
        Ok(Self { adapter })
    }

    pub async fn scan_profile(
        &self,
        profile: BleProfile,
        duration: Duration,
    ) -> BleResult<Vec<DiscoveredDevice>> {
        let service = profile.service_uuid;
        let filter = ScanFilter {
            services: vec![service],
        };

        self.adapter.start_scan(filter).await?;
        time::sleep(duration).await;

        let mut devices = Vec::new();
        for peripheral in self.adapter.peripherals().await? {
            if let Some(info) = DeviceInfo::fetch(&peripheral).await?
                && info.services.contains(&service)
            {
                devices.push(DiscoveredDevice::new(info, peripheral));
            }
        }
        self.adapter.stop_scan().await?;
        Ok(devices)
    }
}
