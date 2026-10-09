use ble_transport::DeviceInfo as RawDeviceInfo;

use super::Uuid;

pub type BleDeviceInfo = RawDeviceInfo;

#[uniffi::remote(Record)]
pub struct BleDeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub services: Vec<Uuid>,
}
