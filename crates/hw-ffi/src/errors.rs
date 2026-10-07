use ble_transport::BleError;
use hw_wallet::{WalletError, WalletErrorKind};
use trezor_connect::thp::{BackendError, ThpWorkflowError};

#[derive(Debug, uniffi::Error, thiserror::Error, Clone)]
#[uniffi(flat_error)]
pub enum HWCoreError {
    #[error("{0}")]
    Ble(String),
    #[error("{0}")]
    Workflow(String),
    #[error("{0}")]
    Device(String),
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Timeout(String),
    #[error("{0}")]
    Unknown(String),
}

impl HWCoreError {
    pub fn message(msg: impl Into<String>) -> Self {
        Self::Unknown(msg.into())
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Ble(_) => "BLE",
            Self::Workflow(_) => "WORKFLOW",
            Self::Device(_) => "DEVICE",
            Self::Validation(_) => "VALIDATION",
            Self::Timeout(_) => "TIMEOUT",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Ble(msg)
            | Self::Workflow(msg)
            | Self::Device(msg)
            | Self::Validation(msg)
            | Self::Timeout(msg)
            | Self::Unknown(msg) => msg,
        }
    }
}

impl From<&str> for HWCoreError {
    fn from(value: &str) -> Self {
        HWCoreError::message(value)
    }
}

impl From<String> for HWCoreError {
    fn from(value: String) -> Self {
        HWCoreError::message(value)
    }
}

impl HWCoreError {
    fn from_kind(kind: WalletErrorKind, message: String) -> Self {
        match kind {
            WalletErrorKind::Ble => Self::Ble(message),
            WalletErrorKind::Workflow => Self::Workflow(message),
            WalletErrorKind::Device => Self::Device(message),
            WalletErrorKind::Validation => Self::Validation(message),
            WalletErrorKind::Timeout => Self::Timeout(message),
        }
    }
}

impl From<BleError> for HWCoreError {
    fn from(error: BleError) -> Self {
        Self::from_kind(WalletErrorKind::of_ble(&error), error.to_string())
    }
}

impl From<BackendError> for HWCoreError {
    fn from(error: BackendError) -> Self {
        Self::from_kind(WalletErrorKind::of_backend(&error), error.to_string())
    }
}

impl From<ThpWorkflowError> for HWCoreError {
    fn from(error: ThpWorkflowError) -> Self {
        let kind = WalletErrorKind::of_workflow(&error);
        let message = match error {
            ThpWorkflowError::Backend(error) => error.to_string(),
            ThpWorkflowError::Storage(error) => error.to_string(),
            other => other.to_string(),
        };
        Self::from_kind(kind, message)
    }
}

impl From<WalletError> for HWCoreError {
    fn from(error: WalletError) -> Self {
        Self::from_kind(error.kind(), error.to_string())
    }
}
