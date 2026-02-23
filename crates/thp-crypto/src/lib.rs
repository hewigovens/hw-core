//! Cryptographic primitives and transport framing for the Trezor Host Protocol.

pub mod frame;
pub mod noise;
pub mod traits;

pub use frame::{ThpCodecError, ThpFrame, ThpFrameDecoder, encode_frame};
pub use noise::NoiseCipherSuite;
pub use traits::{CipherSuite, CryptoError, Keys};
