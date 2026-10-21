use ble_transport::BleError;
use prost::Message;
use trezor_thp::error::TransportError;

use crate::thp::backend::BackendError;
use crate::thp::proto::ProtoMappingError;

pub(super) const MESSAGE_TYPE_FAILURE: u16 = 3;
const FAILURE_UNEXPECTED_MESSAGE: i32 = 1;
pub(super) const FAILURE_ACTION_CANCELLED: i32 = 4;
const FAILURE_PIN_EXPECTED: i32 = 5;
const FAILURE_PIN_CANCELLED: i32 = 6;
const FAILURE_BUSY: i32 = 15;
const FAILURE_IN_PROGRESS: i32 = 19;
const FAILURE_FIRMWARE_ERROR: i32 = 99;

#[derive(Clone, PartialEq, Message)]
pub(super) struct FailureProto {
    #[prost(int32, optional, tag = "1")]
    pub(super) code: Option<i32>,
    #[prost(string, optional, tag = "2")]
    pub(super) message: Option<String>,
}

impl BackendError {
    /// Maps a firmware `Failure` payload to its protobuf `FailureType` meaning.
    pub(super) fn from_failure(payload: &[u8]) -> Self {
        let Ok(msg) = FailureProto::decode(payload) else {
            return Self::Device("firmware reported failure".into());
        };
        match msg.code {
            Some(FAILURE_UNEXPECTED_MESSAGE) => Self::UnsupportedRequest,
            Some(FAILURE_ACTION_CANCELLED | FAILURE_PIN_CANCELLED) => Self::ActionCancelled,
            Some(FAILURE_PIN_EXPECTED) => Self::PinExpected,
            Some(FAILURE_BUSY | FAILURE_IN_PROGRESS) => Self::DeviceBusy,
            Some(FAILURE_FIRMWARE_ERROR) => Self::DeviceFirmwareError,
            Some(code) => Self::DeviceError {
                code: code as u32,
                message: msg.message.unwrap_or_default(),
            },
            None => Self::Device(
                msg.message
                    .unwrap_or_else(|| "firmware reported failure".into()),
            ),
        }
    }

    pub(super) fn unexpected_signing_message(message_type: u16, chain: &str) -> Self {
        Self::Transport(format!(
            "unexpected message type {message_type} during {chain} sign_tx"
        ))
    }
}

impl From<TransportError> for BackendError {
    fn from(error: TransportError) -> Self {
        match error {
            TransportError::TransportBusy => Self::TransportBusy,
            TransportError::DeviceLocked => Self::DeviceLocked,
            TransportError::UnallocatedChannel => Self::DeviceError {
                code: u8::from(error).into(),
                message: "unallocated channel".into(),
            },
            TransportError::DecryptionFailed => Self::DeviceError {
                code: u8::from(error).into(),
                message: "decryption failed".into(),
            },
        }
    }
}

impl From<trezor_thp::Error> for BackendError {
    fn from(error: trezor_thp::Error) -> Self {
        let reason = match error {
            trezor_thp::Error::UnexpectedInput => "unexpected input",
            trezor_thp::Error::NotReady => "channel not ready",
            trezor_thp::Error::MalformedData => "malformed data",
            trezor_thp::Error::InvalidChecksum => "invalid checksum",
            trezor_thp::Error::InsufficientBuffer => "insufficient buffer",
            trezor_thp::Error::CryptoError => "crypto error",
        };
        Self::Transport(format!("THP: {reason}"))
    }
}

impl From<ProtoMappingError> for BackendError {
    fn from(error: ProtoMappingError) -> Self {
        Self::Transport(error.to_string())
    }
}

impl From<BleError> for BackendError {
    fn from(error: BleError) -> Self {
        match error {
            BleError::Timeout(_) => Self::TransportTimeout,
            BleError::NotificationStreamClosed | BleError::Disconnected => Self::Disconnected,
            other => Self::Transport(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thp_transport_error_codes_map_to_spec_meanings() {
        assert!(matches!(
            BackendError::from(TransportError::TransportBusy),
            BackendError::TransportBusy
        ));
        assert!(matches!(
            BackendError::from(TransportError::DeviceLocked),
            BackendError::DeviceLocked
        ));
        assert!(matches!(
            BackendError::from(TransportError::DecryptionFailed),
            BackendError::DeviceError { code: 3, .. }
        ));
    }

    #[test]
    fn failure_codes_map_to_protobuf_meanings() {
        let failure = |code: i32| {
            let payload = FailureProto {
                code: Some(code),
                message: None,
            }
            .encode_to_vec();
            BackendError::from_failure(&payload)
        };

        assert!(matches!(failure(1), BackendError::UnsupportedRequest));
        assert!(matches!(failure(4), BackendError::ActionCancelled));
        assert!(matches!(failure(5), BackendError::PinExpected));
        assert!(matches!(failure(6), BackendError::ActionCancelled));
        assert!(matches!(failure(15), BackendError::DeviceBusy));
        assert!(matches!(failure(19), BackendError::DeviceBusy));
        assert!(matches!(failure(99), BackendError::DeviceFirmwareError));
        assert!(matches!(
            failure(5 + 256),
            BackendError::DeviceError { code: 261, .. }
        ));
    }

    #[test]
    fn ble_errors_keep_timeout_and_disconnect_meaning() {
        assert!(matches!(
            BackendError::from(BleError::Timeout(std::time::Duration::from_secs(1))),
            BackendError::TransportTimeout
        ));
        assert!(matches!(
            BackendError::from(BleError::NotificationStreamClosed),
            BackendError::Disconnected
        ));
        assert!(matches!(
            BackendError::from(BleError::Disconnected),
            BackendError::Disconnected
        ));
        assert!(matches!(
            BackendError::from(BleError::AdapterUnavailable),
            BackendError::Transport(_)
        ));
    }
}
