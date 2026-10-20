use std::time::Duration;

use thiserror::Error;

pub type BleResult<T> = Result<T, BleError>;

#[derive(Debug, Error)]
pub enum BleError {
    #[error("btleplug error: {0}")]
    Btleplug(btleplug::Error),
    #[error("BLE operation timed out after {0:?}")]
    Timeout(Duration),
    #[error("BLE device disconnected")]
    Disconnected,
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
            btleplug::Error::NotConnected => Self::Disconnected,
            other => Self::Btleplug(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btleplug_timeout_and_disconnect_map_to_typed_variants() {
        let error = BleError::from(btleplug::Error::TimedOut(Duration::from_secs(2)));
        assert!(matches!(error, BleError::Timeout(duration) if duration == Duration::from_secs(2)));
        assert!(matches!(
            BleError::from(btleplug::Error::NotConnected),
            BleError::Disconnected
        ));
    }
}
