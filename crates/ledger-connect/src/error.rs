use ble_transport::BleError;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Ble(#[from] BleError),
    #[error("Ledger operation timed out; reconnect before retrying")]
    Timeout,
    #[error("Ledger connection is unavailable; reconnect before retrying")]
    Disconnected,
    #[error("invalid Ledger response: {0}")]
    Protocol(&'static str),
    #[error("invalid Ledger request: {0}")]
    InvalidInput(&'static str),
    #[error("request rejected on Ledger")]
    Rejected,
    #[error("Ledger is locked; unlock it on the device")]
    Locked,
    #[error("open the {expected} app on Ledger (currently running {actual})")]
    WrongApp {
        expected: &'static str,
        actual: String,
    },
    #[error("Ledger command unsupported; check the active app and its version")]
    Unsupported,
    #[error("Ledger returned status 0x{0:04x}")]
    Status(u16),
}
