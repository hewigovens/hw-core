use thiserror::Error;
use trezor_connect::thp::{BackendError, ThpWorkflowError};

/// High-level category for a [`WalletError`].
///
/// Used to produce machine-readable error codes (see [`WalletError::code`]) and
/// to drive retry / recovery logic in callers without string matching.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WalletErrorKind {
    /// A Bluetooth Low Energy transport error occurred.
    Ble,
    /// An error in the THP (Trezor Host Protocol) workflow.
    Workflow,
    /// The device itself returned an error or is in an unexpected state.
    Device,
    /// The request was invalid (bad path, unsupported feature, etc.).
    Validation,
    /// An operation timed out waiting for a device response.
    Timeout,
}

/// Errors that can occur during high-level hw-wallet operations.
#[derive(Debug, Error)]
pub enum WalletError {
    /// The Trezor Safe 7 BLE profile is not compiled into this binary.
    #[error("trezor-safe7 BLE profile not built into this binary")]
    ProfileUnavailable,
    /// The supplied BIP-32 path string could not be parsed.
    #[error("invalid BIP32 path: {0}")]
    InvalidBip32Path(String),
    /// The BLE peer deleted its pairing records; the OS Bluetooth pairing must
    /// be removed and re-established.
    #[error(
        "BLE peer removed pairing information: remove device from OS Bluetooth settings and pair again"
    )]
    PeerRemovedPairingInfo,
    /// A BLE transport-layer error was reported by [`ble_transport`].
    #[error("BLE error: {0}")]
    Ble(#[from] ble_transport::BleError),
    /// The THP workflow layer returned an error.
    #[error("workflow error: {0}")]
    Workflow(#[from] trezor_connect::thp::ThpWorkflowError),
    /// A cryptographic signing operation failed.
    #[error("signing error: {0}")]
    Signing(String),
}

/// Convenience type alias for wallet operation results.
pub type WalletResult<T> = std::result::Result<T, WalletError>;

impl WalletError {
    /// Returns the high-level [`WalletErrorKind`] for this error.
    ///
    /// Useful for branching on error category without exhaustive pattern
    /// matching on the full error type.
    pub fn kind(&self) -> WalletErrorKind {
        match self {
            Self::ProfileUnavailable | Self::InvalidBip32Path(_) | Self::Signing(_) => {
                WalletErrorKind::Validation
            }
            Self::PeerRemovedPairingInfo => WalletErrorKind::Device,
            Self::Ble(error) => {
                if error.to_string().to_ascii_lowercase().contains("timeout") {
                    WalletErrorKind::Timeout
                } else {
                    WalletErrorKind::Ble
                }
            }
            Self::Workflow(error) => classify_workflow_error(error),
        }
    }

    /// Returns a short uppercase string code for this error (e.g. `"BLE"`,
    /// `"TIMEOUT"`).
    ///
    /// Suitable for use in JSON API responses or structured logs.
    pub fn code(&self) -> &'static str {
        match self.kind() {
            WalletErrorKind::Ble => "BLE",
            WalletErrorKind::Workflow => "WORKFLOW",
            WalletErrorKind::Device => "DEVICE",
            WalletErrorKind::Validation => "VALIDATION",
            WalletErrorKind::Timeout => "TIMEOUT",
        }
    }
}

fn classify_workflow_error(error: &ThpWorkflowError) -> WalletErrorKind {
    match error {
        ThpWorkflowError::Backend(BackendError::TransportTimeout) => WalletErrorKind::Timeout,
        ThpWorkflowError::Backend(
            BackendError::Device(_)
            | BackendError::DeviceBusy
            | BackendError::DeviceFirmwareBusy
            | BackendError::SessionConfirmationRequired
            | BackendError::DeviceError { .. },
        ) => WalletErrorKind::Device,
        ThpWorkflowError::Backend(BackendError::UnsupportedPairingMethod) => {
            WalletErrorKind::Validation
        }
        ThpWorkflowError::Backend(BackendError::Transport(_) | BackendError::TransportBusy) => {
            WalletErrorKind::Workflow
        }
        _ => WalletErrorKind::Workflow,
    }
}
