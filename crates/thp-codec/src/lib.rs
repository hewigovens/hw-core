//! Framing helpers for the Trezor Host Protocol transport layer.

pub mod frame;

pub use frame::{ThpCodecError, ThpFrame, ThpFrameDecoder, encode_frame};
