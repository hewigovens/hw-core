use btleplug::platform::Peripheral;

use crate::{BleLink, BleProfile, BleResult, DeviceInfo};

pub struct BleSession {
    device: DeviceInfo,
    link: BleLink,
}

impl BleSession {
    pub(crate) async fn new(
        peripheral: Peripheral,
        profile: BleProfile,
        device: DeviceInfo,
    ) -> BleResult<Self> {
        let link = BleLink::open(peripheral, profile, &device).await?;
        Ok(Self { device, link })
    }

    pub fn into_parts(self) -> (DeviceInfo, BleLink) {
        (self.device, self.link)
    }
}
