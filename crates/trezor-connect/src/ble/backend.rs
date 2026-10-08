use std::time::Duration;

use ble_transport::{BleLink, BleSession};
use tracing::trace;
use trezor_thp::channel::buffered::Buffered;
use trezor_thp::channel::host::Mux;
use trezor_thp::channel::{PairingState, Phase};

use super::channel::{NoiseBackend, ThpChannel};
use super::credentials::SharedCredentials;
use super::errors::MESSAGE_TYPE_FAILURE;
use super::link::{PacketLink, SESSION_ID};
use super::nfc::NfcSecret;
use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{EncodedMessage, ProtoMappingError};
use crate::thp::types::HandshakeCompletionState;

pub struct BleBackend {
    pub(super) link: BleLink,
    handshake_timeout: Duration,
    pub(super) channel: ThpChannel,
    pub(super) credentials: SharedCredentials,
    pub(super) nfc_secret: Option<NfcSecret>,
}

impl BleBackend {
    pub fn new(link: BleLink, handshake_timeout: Duration) -> Self {
        Self {
            link,
            handshake_timeout,
            channel: ThpChannel::Closed,
            credentials: SharedCredentials::default(),
            nfc_secret: None,
        }
    }

    pub fn from_session(session: BleSession, handshake_timeout: Duration) -> Self {
        let (_, link) = session.into_parts();
        Self::new(link, handshake_timeout)
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    pub(super) fn send(&mut self, message: &EncodedMessage) -> BackendResult<()> {
        trace!(
            message_type = message.message_type,
            len = message.payload.len(),
            "THP send"
        );
        Ok(self.channel.established()?.message_in(
            SESSION_ID,
            message.message_type,
            &message.payload,
        )?)
    }

    /// Receives the next message without interpreting a device `Failure`.
    pub(super) async fn receive_raw(&mut self) -> BackendResult<(u16, Vec<u8>)> {
        let channel = self.channel.established()?;
        self.link
            .receive_message(channel, self.handshake_timeout)
            .await
    }

    pub(super) async fn receive(&mut self) -> BackendResult<(u16, Vec<u8>)> {
        let (message_type, payload) = self.receive_raw().await?;
        if message_type == MESSAGE_TYPE_FAILURE {
            return Err(BackendError::from_failure(&payload));
        }
        Ok((message_type, payload))
    }

    pub(super) async fn request(
        &mut self,
        message: EncodedMessage,
    ) -> BackendResult<(u16, Vec<u8>)> {
        self.send(&message)?;
        self.receive().await
    }

    pub(super) async fn call<T>(
        &mut self,
        message: EncodedMessage,
        decode: impl FnOnce(u16, &[u8]) -> Result<T, ProtoMappingError>,
    ) -> BackendResult<T> {
        let (message_type, payload) = self.request(message).await?;
        Ok(decode(message_type, &payload)?)
    }

    pub(super) async fn allocate_channel(&mut self, try_to_unlock: bool) -> BackendResult<()> {
        let mut mux = Buffered::new(Mux::<NoiseBackend>::new());
        mux.set_packet_len(self.link.mtu());
        mux.request_channel(try_to_unlock);
        self.link
            .pump(&mut mux, self.handshake_timeout, |_, result| {
                result.got_channel()
            })
            .await?;
        let open = mux.map(|mux| mux.complete(self.credentials.clone()))?;
        self.channel = ThpChannel::Opening(Box::new(open));
        Ok(())
    }

    pub(super) async fn run_handshake(&mut self) -> BackendResult<HandshakeCompletionState> {
        let ThpChannel::Opening(mut open) =
            std::mem::replace(&mut self.channel, ThpChannel::Closed)
        else {
            return Err(BackendError::Transport(
                "THP handshake requires an allocated channel".into(),
            ));
        };
        self.link
            .pump(&mut open, self.handshake_timeout, |open, _| {
                open.handshake_done() || open.handshake_failed()
            })
            .await?;
        if open.handshake_failed() {
            return Err(BackendError::Transport("THP handshake failed".into()));
        }
        let channel = (*open).map(|open| open.complete())?;
        let state = match channel.phase() {
            Phase::PairingCredential {
                handshake_pairing_state: PairingState::Unpaired,
            } => HandshakeCompletionState::RequiresPairing,
            Phase::PairingCredential {
                handshake_pairing_state: PairingState::Paired,
            }
            | Phase::EncryptedTransport => HandshakeCompletionState::Paired,
            Phase::PairingCredential {
                handshake_pairing_state: PairingState::PairedAutoconnect,
            } => HandshakeCompletionState::AutoPaired,
        };
        self.channel = ThpChannel::Open(Box::new(channel));
        Ok(state)
    }

    pub(super) fn handshake_hash(&mut self) -> BackendResult<Vec<u8>> {
        Ok(self.channel.established()?.handshake_hash().to_vec())
    }

    pub(super) fn end_pairing(&mut self) -> BackendResult<()> {
        self.channel.established()?.end_pairing();
        Ok(())
    }

    pub(super) fn reset_channel(&mut self) {
        self.channel = ThpChannel::Closed;
        self.nfc_secret = None;
    }
}
