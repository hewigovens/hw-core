use trezor_thp::ChannelIO;
use trezor_thp::channel::buffered::Buffered;
use trezor_thp::channel::host::{Channel, ChannelOpen, Mux};

use super::credentials::SharedCredentials;
use crate::thp::backend::{BackendError, BackendResult};

pub(super) enum NoiseBackend {}

impl trezor_thp::Backend for NoiseBackend {
    type DH = trezor_noise_rust_crypto::X25519;
    type Cipher = trezor_noise_rust_crypto::Aes256Gcm;
    type Hash = trezor_noise_rust_crypto::Sha256;

    fn random_bytes(dest: &mut [u8]) {
        rand::fill(dest);
    }
}

pub(super) type OpeningChannel = Buffered<ChannelOpen<SharedCredentials, NoiseBackend>>;
pub(super) type OpenChannel = Buffered<Channel<NoiseBackend>>;

pub(super) enum ThpChannel {
    Closed,
    Opening(Box<OpeningChannel>),
    Open(Box<OpenChannel>),
}

impl ThpChannel {
    pub(super) fn established(&mut self) -> BackendResult<&mut OpenChannel> {
        match self {
            Self::Open(channel) => Ok(channel),
            Self::Closed | Self::Opening(_) => Err(BackendError::Transport(
                "THP channel is not established".into(),
            )),
        }
    }
}

/// A THP channel the pump can drive, exposing its pending retransmission count.
pub(super) trait PumpChannel: ChannelIO {
    fn retry_count(&self) -> Option<u8>;
}

impl PumpChannel for Mux<NoiseBackend> {
    fn retry_count(&self) -> Option<u8> {
        None
    }
}

impl PumpChannel for ChannelOpen<SharedCredentials, NoiseBackend> {
    fn retry_count(&self) -> Option<u8> {
        self.sending_retry()
    }
}

impl PumpChannel for Channel<NoiseBackend> {
    fn retry_count(&self) -> Option<u8> {
        self.sending_retry()
    }
}
