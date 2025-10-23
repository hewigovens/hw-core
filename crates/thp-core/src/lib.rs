//! Core host state machine for the Trezor Host Protocol.

pub mod error;
pub mod link;
pub mod session;
pub mod trust;

pub use error::ThpError;
pub use link::Link;
pub use session::{HandshakeEvent, HandshakeOpts, ThpSession};
pub use trust::{MemoryTrustStore, TrustStore, TrustedPeer};
