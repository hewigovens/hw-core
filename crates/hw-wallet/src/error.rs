use ble_transport::BleError;
use thiserror::Error;
use trezor_connect::thp::{BackendError, ThpWorkflowError};

/// Failure classes an app can map to distinct screens without matching message text.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WalletErrorKind {
    Ble,
    Workflow,
    Device,
    Validation,
    Timeout,
    /// The user rejected the request on the device, or cancelled PIN entry.
    ActionCancelled,
    /// The device is locked and expects PIN entry.
    DeviceLocked,
    /// The device is busy with another action.
    DeviceBusy,
    /// The device must confirm this host's connection before continuing.
    ConnectionConfirmationRequired,
    /// The device no longer knows this host; pair again.
    PairingRequired,
    /// The BLE link dropped during the operation.
    Disconnected,
    /// The firmware does not support the request; it may be too old.
    Unsupported,
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid BIP32 path: {0}")]
    InvalidBip32Path(String),
    #[error(
        "BLE peer removed pairing information: remove device from OS Bluetooth settings and pair again"
    )]
    PeerRemovedPairingInfo,
    #[error("BLE error: {0}")]
    Ble(#[from] BleError),
    #[error("workflow error: {0}")]
    Workflow(#[from] ThpWorkflowError),
    #[error("signing error: {0}")]
    Signing(String),
    #[error(
        "solana serialized tx is too short ({len} bytes, minimum {min}); provide full serialized transaction bytes"
    )]
    SolanaTxTooShort { len: usize, min: usize },
    #[error("Solana transaction version {0} is not supported by firmware")]
    UnsupportedSolanaTxVersion(u8),
    /// A session could not be created; `hint` tells the user how to recover.
    #[error("{hint}")]
    SessionUnavailable {
        hint: &'static str,
        #[source]
        source: ThpWorkflowError,
    },
}

pub type WalletResult<T> = std::result::Result<T, WalletError>;

impl WalletError {
    pub fn kind(&self) -> WalletErrorKind {
        match self {
            Self::InvalidBip32Path(_)
            | Self::Signing(_)
            | Self::SolanaTxTooShort { .. }
            | Self::UnsupportedSolanaTxVersion(_) => WalletErrorKind::Validation,
            Self::PeerRemovedPairingInfo => WalletErrorKind::PairingRequired,
            Self::Ble(error) => error.into(),
            Self::Workflow(error) | Self::SessionUnavailable { source: error, .. } => error.into(),
        }
    }
}

impl From<&BleError> for WalletErrorKind {
    fn from(error: &BleError) -> Self {
        match error {
            BleError::Timeout(_) => Self::Timeout,
            BleError::Disconnected | BleError::NotificationStreamClosed => Self::Disconnected,
            BleError::Btleplug(_)
            | BleError::AdapterUnavailable
            | BleError::MissingCharacteristic { .. } => Self::Ble,
        }
    }
}

impl From<&ThpWorkflowError> for WalletErrorKind {
    fn from(error: &ThpWorkflowError) -> Self {
        match error {
            ThpWorkflowError::Backend(error) => error.into(),
            ThpWorkflowError::PairingInteractionRequired => Self::PairingRequired,
            ThpWorkflowError::InvalidPhase
            | ThpWorkflowError::MissingHandshake
            | ThpWorkflowError::MissingHandshakeCredentials
            | ThpWorkflowError::AlreadyPaired
            | ThpWorkflowError::NoCommonPairingMethod
            | ThpWorkflowError::PairingAborted
            | ThpWorkflowError::PairingController(_)
            | ThpWorkflowError::UnexpectedPairingResponse
            | ThpWorkflowError::Storage(_) => Self::Workflow,
        }
    }
}

impl From<&BackendError> for WalletErrorKind {
    fn from(error: &BackendError) -> Self {
        match error {
            BackendError::TransportTimeout => Self::Timeout,
            BackendError::Disconnected => Self::Disconnected,
            BackendError::ActionCancelled => Self::ActionCancelled,
            BackendError::DeviceLocked | BackendError::PinExpected => Self::DeviceLocked,
            BackendError::DeviceBusy | BackendError::TransportBusy => Self::DeviceBusy,
            BackendError::SessionConfirmationRequired => Self::ConnectionConfirmationRequired,
            BackendError::UnsupportedRequest => Self::Unsupported,
            BackendError::Device(_)
            | BackendError::DeviceFirmwareError
            | BackendError::DeviceError { .. } => Self::Device,
            BackendError::UnsupportedPairingMethod => Self::Validation,
            BackendError::Transport(_) => Self::Workflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ble_errors_are_classified_by_variant() {
        let cases = [
            (
                BleError::Timeout(Duration::from_secs(1)),
                WalletErrorKind::Timeout,
            ),
            (BleError::Disconnected, WalletErrorKind::Disconnected),
            (
                BleError::NotificationStreamClosed,
                WalletErrorKind::Disconnected,
            ),
            (BleError::AdapterUnavailable, WalletErrorKind::Ble),
        ];
        for (error, kind) in cases {
            assert_eq!(WalletError::Ble(error).kind(), kind);
        }
    }

    #[test]
    fn device_failures_are_classified_for_distinct_app_screens() {
        let cases = [
            (
                BackendError::ActionCancelled,
                WalletErrorKind::ActionCancelled,
            ),
            (BackendError::PinExpected, WalletErrorKind::DeviceLocked),
            (BackendError::DeviceLocked, WalletErrorKind::DeviceLocked),
            (BackendError::DeviceBusy, WalletErrorKind::DeviceBusy),
            (
                BackendError::SessionConfirmationRequired,
                WalletErrorKind::ConnectionConfirmationRequired,
            ),
            (BackendError::Disconnected, WalletErrorKind::Disconnected),
            (BackendError::TransportTimeout, WalletErrorKind::Timeout),
            (
                BackendError::UnsupportedRequest,
                WalletErrorKind::Unsupported,
            ),
        ];
        for (error, kind) in cases {
            assert_eq!(
                WalletError::from(ThpWorkflowError::Backend(error)).kind(),
                kind
            );
        }
        assert_eq!(
            WalletError::from(ThpWorkflowError::PairingInteractionRequired).kind(),
            WalletErrorKind::PairingRequired
        );
        assert_eq!(
            WalletError::PeerRemovedPairingInfo.kind(),
            WalletErrorKind::PairingRequired
        );
    }
}
