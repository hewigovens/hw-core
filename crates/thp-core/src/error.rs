use snow::Error as NoiseError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThpError {
    #[error("link_error: {0}")]
    Link(anyhow::Error),
    #[error("codec_error: {0}")]
    Codec(#[from] thp_crypto::ThpCodecError),
    #[error("crypto_error: {0}")]
    Crypto(#[from] thp_crypto::CryptoError),
    #[error("noise_error: {0}")]
    Noise(#[from] NoiseError),
    #[error("peer_static_mismatch")]
    PeerStaticMismatch,
    #[error("missing_remote_static_key")]
    MissingRemoteStatic,
    #[error("unexpected_msg_id: expected {expected}, got {actual}")]
    UnexpectedMsgId { expected: u32, actual: u32 },
    #[error("timeout")]
    Timeout,
}

impl From<anyhow::Error> for ThpError {
    fn from(err: anyhow::Error) -> Self {
        ThpError::Link(err)
    }
}
