use std::time::Duration;

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct BleProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub service_uuid: Uuid,
    pub write_uuid: Uuid,
    pub notify_uuid: Uuid,
    pub push_uuid: Option<Uuid>,
    pub mtu_hint: Option<u16>,
}

impl BleProfile {
    pub const TREZOR_SAFE7: Self = Self {
        id: "trezor_safe7",
        name: "Trezor Safe 7",
        service_uuid: uuid::uuid!("8c000001-a59b-4d58-a9ad-073df69fa1b1"),
        write_uuid: uuid::uuid!("8c000002-a59b-4d58-a9ad-073df69fa1b1"),
        notify_uuid: uuid::uuid!("8c000003-a59b-4d58-a9ad-073df69fa1b1"),
        push_uuid: Some(uuid::uuid!("8c000004-a59b-4d58-a9ad-073df69fa1b1")),
        mtu_hint: Some(244),
    };
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub services: Vec<Uuid>,
}

#[derive(Debug, Error)]
pub enum BleError {
    #[error("btleplug error: {0}")]
    Btleplug(btleplug::Error),
    #[error("BLE operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("no BLE adapter available")]
    AdapterUnavailable,
    #[error("BLE notification stream closed unexpectedly")]
    NotificationStreamClosed,
    #[error("required characteristic {kind} not found for profile {profile}")]
    MissingCharacteristic {
        kind: &'static str,
        profile: &'static str,
    },
}

impl From<btleplug::Error> for BleError {
    fn from(error: btleplug::Error) -> Self {
        match error {
            btleplug::Error::TimedOut(duration) => Self::Timeout(duration),
            other => Self::Btleplug(other),
        }
    }
}

impl BleError {
    pub fn missing(kind: &'static str, profile: BleProfile) -> Self {
        Self::MissingCharacteristic {
            kind,
            profile: profile.id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btleplug_timeout_maps_to_typed_variant() {
        let error = BleError::from(btleplug::Error::TimedOut(Duration::from_secs(2)));
        assert!(matches!(error, BleError::Timeout(duration) if duration == Duration::from_secs(2)));
    }
}
