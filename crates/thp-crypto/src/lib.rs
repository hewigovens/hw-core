//! Cryptographic primitives for the Trezor Host Protocol.

pub mod noise;
pub mod traits;

pub use noise::NoiseCipherSuite;
pub use traits::{CipherSuite, CryptoError, Keys};
