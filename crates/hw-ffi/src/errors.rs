/// Simplified error surface exposed via UniFFI bindings.
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

impl From<ble_transport::BleError> for HWCoreError {
    fn from(error: ble_transport::BleError) -> Self {
        HWCoreError::Ble(error.to_string())
    }
}

impl From<trezor_connect::thp::BackendError> for HWCoreError {
    fn from(error: trezor_connect::thp::BackendError) -> Self {
        use trezor_connect::thp::BackendError;

        match error {
            BackendError::TransportTimeout => HWCoreError::Timeout(error.to_string()),
            BackendError::DeviceBusy
            | BackendError::DeviceFirmwareBusy
            | BackendError::SessionConfirmationRequired
            | BackendError::DeviceError { .. }
            | BackendError::Device(_) => HWCoreError::Device(error.to_string()),
            BackendError::TransportBusy | BackendError::Transport(_) => {
                HWCoreError::Workflow(error.to_string())
            }
            BackendError::UnsupportedPairingMethod => {
                HWCoreError::Validation("unsupported pairing method".to_string())
            }
        }
    }
}

impl From<trezor_connect::thp::ThpWorkflowError> for HWCoreError {
    fn from(error: trezor_connect::thp::ThpWorkflowError) -> Self {
        use trezor_connect::thp::ThpWorkflowError;

        match error {
            ThpWorkflowError::Backend(backend_err) => HWCoreError::from(backend_err),
            ThpWorkflowError::InvalidPhase
            | ThpWorkflowError::MissingHandshake
            | ThpWorkflowError::MissingHandshakeCredentials
            | ThpWorkflowError::AlreadyPaired
            | ThpWorkflowError::NonceMismatch
            | ThpWorkflowError::NoCommonPairingMethod
            | ThpWorkflowError::PairingAborted
            | ThpWorkflowError::PairingInteractionRequired
            | ThpWorkflowError::PairingController(_) => HWCoreError::Workflow(error.to_string()),
            ThpWorkflowError::Storage(message) => HWCoreError::Workflow(message.to_string()),
        }
    }
}

impl From<hw_wallet::WalletError> for HWCoreError {
    fn from(error: hw_wallet::WalletError) -> Self {
        use hw_wallet::error::WalletErrorKind;

        match error.kind() {
            WalletErrorKind::Ble => HWCoreError::Ble(error.to_string()),
            WalletErrorKind::Workflow => HWCoreError::Workflow(error.to_string()),
            WalletErrorKind::Device => HWCoreError::Device(error.to_string()),
            WalletErrorKind::Validation => HWCoreError::Validation(error.to_string()),
            WalletErrorKind::Timeout => HWCoreError::Timeout(error.to_string()),
        }
    }
}
