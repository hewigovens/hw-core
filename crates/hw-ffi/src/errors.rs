/// Simplified error surface exposed via UniFFI bindings.
#[derive(Debug, uniffi::Error, thiserror::Error, Clone)]
#[uniffi(flat_error)]
pub enum HWCoreError {
    #[error("{0}")]
    Message(String),
}

impl HWCoreError {
    pub fn message(msg: impl Into<String>) -> Self {
        Self::Message(msg.into())
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
        HWCoreError::message(error.to_string())
    }
}

impl From<trezor_connect::thp::BackendError> for HWCoreError {
    fn from(error: trezor_connect::thp::BackendError) -> Self {
        HWCoreError::message(error.to_string())
    }
}

impl From<trezor_connect::thp::ThpWorkflowError> for HWCoreError {
    fn from(error: trezor_connect::thp::ThpWorkflowError) -> Self {
        HWCoreError::message(error.to_string())
    }
}
