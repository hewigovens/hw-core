use std::time::Duration;

use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::{Adapter, Manager, Peripheral};
use tokio::time;

use crate::profile::DeviceInfo;
use crate::{BleError, BleProfile, BleResult};

pub struct BleManager {
    adapter: Adapter,
}

impl BleManager {
    pub async fn new() -> BleResult<Self> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let adapter = adapters
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

        let peripherals = self.adapter.peripherals().await?;
        let mut devices = Vec::new();
        for peripheral in peripherals {
            if let Some(info) = fetch_device_info(&peripheral).await?
                && info.services.contains(&service)
            {
                devices.push(DiscoveredDevice { info, peripheral });
            }
        }
        self.adapter.stop_scan().await?;
        Ok(devices)
    }
}

pub struct DiscoveredDevice {
    info: DeviceInfo,
    pub(crate) peripheral: Peripheral,
}

impl DiscoveredDevice {
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    pub fn into_parts(self) -> (DeviceInfo, Peripheral) {
        (self.info, self.peripheral)
    }
}

async fn fetch_device_info(peripheral: &Peripheral) -> BleResult<Option<DeviceInfo>> {
    let properties = match peripheral.properties().await? {
        Some(props) => props,
        None => return Ok(None),
    };

    Ok(Some(DeviceInfo {
        id: peripheral.id().to_string(),
        name: properties.local_name.clone(),
        rssi: properties.rssi.map(|value| value as i32),
        services: properties.services.clone(),
    }))
}
