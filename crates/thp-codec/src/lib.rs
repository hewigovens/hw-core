//! Framing helpers for the Trezor Host Protocol transport layer.

pub mod frame;

pub use frame::{encode_frame, ThpCodecError, ThpFrame, ThpFrameDecoder};
