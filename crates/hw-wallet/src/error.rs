use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("trezor-safe7 BLE profile not built into this binary")]
    ProfileUnavailable,
    #[error("BLE error: {0}")]
    Ble(#[from] ble_transport::BleError),
    #[error("workflow error: {0}")]
    Workflow(#[from] trezor_connect::thp::ThpWorkflowError),
}

pub type WalletResult<T> = std::result::Result<T, WalletError>;
