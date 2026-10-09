use ble_transport::BleError;
use prost::Message;
use trezor_thp::error::TransportError;

use crate::thp::backend::BackendError;
use crate::thp::proto::ProtoMappingError;

pub(super) const MESSAGE_TYPE_FAILURE: u16 = 3;
const FAILURE_PIN_EXPECTED: i32 = 5;
const FAILURE_BUSY: i32 = 15;
const FAILURE_FIRMWARE_ERROR: i32 = 99;

#[derive(Clone, PartialEq, Message)]
struct FailureProto {
    #[prost(int32, optional, tag = "1")]
    code: Option<i32>,
    #[prost(string, optional, tag = "2")]
    message: Option<String>,
}

impl BackendError {
    /// Maps a firmware `Failure` payload to its protobuf `FailureType` meaning.
    pub(super) fn from_failure(payload: &[u8]) -> Self {
        let Ok(msg) = FailureProto::decode(payload) else {
            return Self::Device("firmware reported failure".into());
        };
        match msg.code {
            Some(FAILURE_PIN_EXPECTED) => Self::PinExpected,
            Some(FAILURE_BUSY) => Self::DeviceBusy,
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
        Self::Transport(error.to_string())
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

        assert!(matches!(failure(5), BackendError::PinExpected));
        assert!(matches!(failure(15), BackendError::DeviceBusy));
        assert!(matches!(failure(99), BackendError::DeviceFirmwareError));
        assert!(matches!(
            failure(5 + 256),
            BackendError::DeviceError { code: 261, .. }
        ));
    }
}
