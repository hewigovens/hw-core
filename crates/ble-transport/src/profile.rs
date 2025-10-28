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
    pub mtu_hint: Option<u16>,
    pub preferred_scan_duration: Option<Duration>,
}

impl BleProfile {
    pub fn trezor_safe7() -> Option<Self> {
        #[cfg(feature = "trezor-safe7")]
        {
            Some(Self {
                id: "trezor_safe7",
                name: "Trezor Safe 7",
                service_uuid: uuid::uuid!("8c000001-a59b-4d58-a9ad-073df69fa1b1"),
                write_uuid: uuid::uuid!("8c000002-a59b-4d58-a9ad-073df69fa1b1"),
                notify_uuid: uuid::uuid!("8c000003-a59b-4d58-a9ad-073df69fa1b1"),
                mtu_hint: Some(244),
                preferred_scan_duration: Some(Duration::from_secs(3)),
            })
        }
        #[cfg(not(feature = "trezor-safe7"))]
        {
            None
        }
    }
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
    Btleplug(#[from] btleplug::Error),
    #[error("no BLE adapter available")]
    AdapterUnavailable,
    #[error("timeout waiting for BLE notification")]
    NotificationTimeout,
    #[error("BLE notification stream closed unexpectedly")]
    NotificationStreamClosed,
    #[error("required characteristic {kind} not found for profile {profile}")]
    MissingCharacteristic {
        kind: &'static str,
        profile: &'static str,
    },
}

impl BleError {
    pub fn missing(kind: &'static str, profile: BleProfile) -> Self {
        Self::MissingCharacteristic {
            kind,
            profile: profile.id,
        }
    }
}

pub struct KnownProfiles;

impl KnownProfiles {
    pub fn trezor_safe7() -> Option<BleProfile> {
        BleProfile::trezor_safe7()
    }
}
