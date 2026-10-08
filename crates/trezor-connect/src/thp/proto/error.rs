use hw_chain::Chain;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoMappingError {
    #[error("prost decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid enum value: {0}")]
    InvalidEnum(i32),
    #[error("invalid hex string")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("unsupported chain: {0:?}")]
    UnsupportedChain(Chain),
    #[error("unexpected message type {0}")]
    UnexpectedMessage(u16),
    #[error("message is not valid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}
