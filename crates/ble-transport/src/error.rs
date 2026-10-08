use std::time::Duration;

use thiserror::Error;

pub type BleResult<T> = Result<T, BleError>;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btleplug_timeout_maps_to_typed_variant() {
        let error = BleError::from(btleplug::Error::TimedOut(Duration::from_secs(2)));
        assert!(matches!(error, BleError::Timeout(duration) if duration == Duration::from_secs(2)));
    }
}
