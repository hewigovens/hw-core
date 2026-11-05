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
    #[error("invalid BIP32 path: {0}")]
    InvalidBip32Path(&'static str),
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
    #[error(
        "Ledger Solana rejected the OCMS header; use an app version with OCMS v1 support. Legacy formats are not substituted automatically"
    )]
    SolanaMessageHeaderUnsupported,
    #[error(
        "Ledger Solana cannot process this request; blind signing may be required, or the operation may be unsupported by this app"
    )]
    SolanaBlindSigningRequired,
    #[error("Ledger returned status 0x{0:04x}")]
    Status(u16),
}

impl LedgerError {
    /// A final device status ends the command even when the user declines it.
    pub(crate) fn is_device_response(&self) -> bool {
        match self {
            Self::Rejected
            | Self::Locked
            | Self::Unsupported
            | Self::SolanaMessageHeaderUnsupported
            | Self::SolanaBlindSigningRequired => true,
            Self::Status(status) => *status != crate::protocol::STATUS_INTERRUPTED,
            Self::Ble(_)
            | Self::Timeout
            | Self::Disconnected
            | Self::Protocol(_)
            | Self::InvalidInput(_)
            | Self::InvalidBip32Path(_)
            | Self::WrongApp { .. } => false,
        }
    }
}
