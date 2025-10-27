use thiserror::Error;

use super::backend::BackendError;
use super::storage::StorageError;

#[derive(Debug, Error)]
pub enum ThpWorkflowError {
    #[error("thp backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("workflow in invalid phase")]
    InvalidPhase,
    #[error("handshake state missing")]
    MissingHandshake,
    #[error("handshake credentials missing")]
    MissingHandshakeCredentials,
    #[error("pairing already complete")]
    AlreadyPaired,
    #[error("device reported nonce mismatch")]
    NonceMismatch,
    #[error("no matching pairing methods between host and device")]
    NoCommonPairingMethod,
    #[error("pairing aborted by host")]
    PairingAborted,
    #[error("pending pairing interaction required")]
    PairingInteractionRequired,
    #[error("pairing controller error: {0}")]
    PairingController(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

pub type Result<T> = std::result::Result<T, ThpWorkflowError>;
