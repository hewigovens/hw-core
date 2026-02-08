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
    #[error("trezor-safe7 BLE profile not built into this binary")]
    ProfileUnavailable,
    #[error("invalid BIP32 path: {0}")]
    InvalidBip32Path(String),
    #[error(
        "BLE peer removed pairing information: remove device from OS Bluetooth settings and pair again"
    )]
    PeerRemovedPairingInfo,
    #[error("BLE error: {0}")]
    Ble(#[from] ble_transport::BleError),
    #[error("workflow error: {0}")]
    Workflow(#[from] trezor_connect::thp::ThpWorkflowError),
    #[error("signing error: {0}")]
    Signing(String),
}

pub type WalletResult<T> = std::result::Result<T, WalletError>;

impl WalletError {
    pub fn kind(&self) -> WalletErrorKind {
        match self {
            Self::ProfileUnavailable | Self::InvalidBip32Path(_) | Self::Signing(_) => {
                WalletErrorKind::Validation
            }
            Self::PeerRemovedPairingInfo => WalletErrorKind::Device,
            Self::Ble(error) => {
                if contains_timeout(&error.to_string()) {
                    WalletErrorKind::Timeout
                } else {
                    WalletErrorKind::Ble
                }
            }
            Self::Workflow(error) => classify_workflow_error(error),
        }
    }

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
        ThpWorkflowError::Backend(BackendError::Device(_)) => WalletErrorKind::Device,
        ThpWorkflowError::Backend(BackendError::Transport(message)) => {
            if contains_timeout(message) {
                WalletErrorKind::Timeout
            } else {
                WalletErrorKind::Workflow
            }
        }
        ThpWorkflowError::Backend(BackendError::UnsupportedPairingMethod) => {
            WalletErrorKind::Validation
        }
        _ => WalletErrorKind::Workflow,
    }
}

fn contains_timeout(message: &str) -> bool {
    message.to_ascii_lowercase().contains("timeout")
}
