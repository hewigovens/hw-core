use btleplug::api::Peripheral as _;
use btleplug::platform::Peripheral;
use uuid::Uuid;

use crate::{BleProfile, BleResult, BleSession};

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub services: Vec<Uuid>,
}

impl DeviceInfo {
    pub(crate) async fn fetch(peripheral: &Peripheral) -> BleResult<Option<Self>> {
        let Some(properties) = peripheral.properties().await? else {
            return Ok(None);
        };
        Ok(Some(Self {
            id: peripheral.id().to_string(),
            name: properties.local_name,
            rssi: properties.rssi.map(i32::from),
            services: properties.services,
        }))
    }

    pub(crate) fn redacted_id(&self) -> String {
        let chars: Vec<char> = self.id.chars().collect();
        if chars.is_empty() {
            return "<redacted>".to_string();
        }
        let start = chars.len().saturating_sub(6);
        format!("...{}", chars[start..].iter().collect::<String>())
    }
}

pub struct DiscoveredDevice {
    info: DeviceInfo,
    peripheral: Peripheral,
}

impl DiscoveredDevice {
    pub(crate) fn new(info: DeviceInfo, peripheral: Peripheral) -> Self {
        Self { info, peripheral }
    }

    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    pub async fn connect(self, profile: BleProfile) -> BleResult<BleSession> {
        BleSession::new(self.peripheral, profile, self.info).await
    }
}
