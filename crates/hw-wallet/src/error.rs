use ble_transport::BleError;
use thiserror::Error;
use trezor_connect::thp::{BackendError, ThpWorkflowError};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WalletErrorKind {
    Ble,
    Workflow,
    Device,
    Validation,
    Timeout,
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
}

pub type WalletResult<T> = std::result::Result<T, WalletError>;

impl WalletError {
    pub fn kind(&self) -> WalletErrorKind {
        match self {
            Self::InvalidBip32Path(_)
            | Self::Signing(_)
            | Self::SolanaTxTooShort { .. }
            | Self::UnsupportedSolanaTxVersion(_) => WalletErrorKind::Validation,
            Self::PeerRemovedPairingInfo => WalletErrorKind::Device,
            Self::Ble(error) => WalletErrorKind::of_ble(error),
            Self::Workflow(error) => WalletErrorKind::of_workflow(error),
        }
    }
}

impl WalletErrorKind {
    pub fn of_ble(error: &BleError) -> Self {
        match error {
            BleError::Timeout(_) => Self::Timeout,
            BleError::Btleplug(_)
            | BleError::AdapterUnavailable
            | BleError::NotificationStreamClosed
            | BleError::MissingCharacteristic { .. } => Self::Ble,
        }
    }

    pub fn of_workflow(error: &ThpWorkflowError) -> Self {
        match error {
            ThpWorkflowError::Backend(error) => Self::of_backend(error),
            ThpWorkflowError::InvalidPhase
            | ThpWorkflowError::MissingHandshake
            | ThpWorkflowError::MissingHandshakeCredentials
            | ThpWorkflowError::AlreadyPaired
            | ThpWorkflowError::NoCommonPairingMethod
            | ThpWorkflowError::PairingAborted
            | ThpWorkflowError::PairingInteractionRequired
            | ThpWorkflowError::PairingController(_)
            | ThpWorkflowError::Storage(_) => Self::Workflow,
        }
    }

    pub fn of_backend(error: &BackendError) -> Self {
        match error {
            BackendError::TransportTimeout => Self::Timeout,
            BackendError::Device(_)
            | BackendError::DeviceBusy
            | BackendError::DeviceLocked
            | BackendError::PinExpected
            | BackendError::DeviceFirmwareError
            | BackendError::SessionConfirmationRequired
            | BackendError::DeviceError { .. } => Self::Device,
            BackendError::UnsupportedPairingMethod => Self::Validation,
            BackendError::Transport(_) | BackendError::TransportBusy => Self::Workflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn ble_timeout_is_classified_as_timeout() {
        let error = WalletError::Ble(BleError::Timeout(Duration::from_secs(1)));
        assert_eq!(error.kind(), WalletErrorKind::Timeout);
        assert_eq!(
            WalletError::Ble(BleError::AdapterUnavailable).kind(),
            WalletErrorKind::Ble
        );
    }
}
