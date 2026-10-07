use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ble_transport::{BleBackend as TransportBackend, BleLink, BleSession, DeviceInfo};
use prost::Message;
use tokio::time;
use tracing::{debug, trace};
use trezor_thp::ChannelIO;
use trezor_thp::channel::buffered::Buffered;
use trezor_thp::channel::host::{Channel, ChannelOpen, Mux};
use trezor_thp::channel::{
    MAX_RETRANSMISSION_COUNT, PRIVKEY_LEN, PacketInResult, PairingState, Phase, retransmit_after_ms,
};
use trezor_thp::credential::{CredentialStore, FoundCredential};
use trezor_thp::error::TransportError;

use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::crypto::find_known_pairing_credentials;
use crate::thp::messages;
use crate::thp::proto::{EncodedMessage, ProtoMappingError};
use crate::thp::types::{HandshakeCompletionState, KnownCredential};

const SESSION_ID: u8 = 0;
const MESSAGE_TYPE_SUCCESS: u16 = 2;
const MESSAGE_TYPE_CREATE_SESSION: u16 = 1000;
const MESSAGE_TYPE_FAILURE: u16 = 3;
const MESSAGE_TYPE_BUTTON_REQUEST: u16 = messages::ThpMessageType::ButtonRequest as i32 as u16;
const MESSAGE_TYPE_BUTTON_ACK: u16 = messages::ThpMessageType::ButtonAck as i32 as u16;
const FAILURE_PIN_EXPECTED: i32 = 5;
const FAILURE_BUSY: i32 = 15;
const FAILURE_FIRMWARE_ERROR: i32 = 99;
const MAX_BUSY_BACKOFF_MS: u64 = 500;

#[derive(Clone, PartialEq, Message)]
struct FailureProto {
    #[prost(int32, optional, tag = "1")]
    code: Option<i32>,
    #[prost(string, optional, tag = "2")]
    message: Option<String>,
}

fn decode_failure_as_backend_error(payload: &[u8]) -> BackendError {
    let Ok(msg) = FailureProto::decode(payload) else {
        return BackendError::Device("firmware reported failure".into());
    };
    match msg.code {
        Some(FAILURE_PIN_EXPECTED) => BackendError::PinExpected,
        Some(FAILURE_BUSY) => BackendError::DeviceBusy,
        Some(FAILURE_FIRMWARE_ERROR) => BackendError::DeviceFirmwareError,
        Some(code) => BackendError::DeviceError {
            code: code as u32,
            message: msg.message.unwrap_or_default(),
        },
        None => BackendError::Device(
            msg.message
                .unwrap_or_else(|| "firmware reported failure".into()),
        ),
    }
}

fn backend_error_from_transport(error: TransportError) -> BackendError {
    match error {
        TransportError::TransportBusy => BackendError::TransportBusy,
        TransportError::DeviceLocked => BackendError::DeviceLocked,
        TransportError::UnallocatedChannel => BackendError::DeviceError {
            code: u8::from(error).into(),
            message: "unallocated channel".into(),
        },
        TransportError::DecryptionFailed => BackendError::DeviceError {
            code: u8::from(error).into(),
            message: "decryption failed".into(),
        },
    }
}

fn thp_error(error: trezor_thp::Error) -> BackendError {
    let reason = match error {
        trezor_thp::Error::UnexpectedInput => "unexpected input",
        trezor_thp::Error::NotReady => "channel not ready",
        trezor_thp::Error::MalformedData => "malformed data",
        trezor_thp::Error::InvalidChecksum => "invalid checksum",
        trezor_thp::Error::InsufficientBuffer => "insufficient buffer",
        trezor_thp::Error::CryptoError => "crypto error",
    };
    BackendError::Transport(format!("THP: {reason}"))
}

fn mapping_error(error: ProtoMappingError) -> BackendError {
    BackendError::Transport(error.to_string())
}

pub(crate) enum NoiseBackend {}

impl trezor_thp::Backend for NoiseBackend {
    type DH = trezor_noise_rust_crypto::X25519;
    type Cipher = trezor_noise_rust_crypto::Aes256Gcm;
    type Hash = trezor_noise_rust_crypto::Sha256;

    fn random_bytes(dest: &mut [u8]) {
        rand::fill(dest);
    }
}

#[derive(Default)]
struct HostCredentials {
    static_key: [u8; PRIVKEY_LEN],
    known: Vec<KnownCredential>,
    selected: Option<KnownCredential>,
}

/// Always supplies the persistent host key so issued credentials stay bound to it.
#[derive(Clone, Default)]
struct SharedCredentials(Arc<Mutex<HostCredentials>>);

impl SharedCredentials {
    fn lock(&self) -> std::sync::MutexGuard<'_, HostCredentials> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl CredentialStore for SharedCredentials {
    fn lookup<'a>(
        &self,
        ephemeral_pubkey: &[u8],
        masked_static_pubkey: &[u8],
        dest: &'a mut [u8],
    ) -> Option<FoundCredential<'a>> {
        let mut credentials = self.lock();
        let ephemeral: &[u8; 32] = ephemeral_pubkey.try_into().ok()?;
        let masked: &[u8; 32] = masked_static_pubkey.try_into().ok()?;
        let selected = find_known_pairing_credentials(&credentials.known, masked, ephemeral)
            .into_iter()
            .next();
        let payload = messages::ThpHandshakeCompletionReqNoisePayload {
            host_pairing_credential: selected
                .as_ref()
                .and_then(|c| hex::decode(&c.credential).ok()),
        }
        .encode_to_vec();
        credentials.selected = selected;

        if dest.len() < PRIVKEY_LEN + payload.len() {
            return None;
        }
        let (key, rest) = dest.split_at_mut(PRIVKEY_LEN);
        key.copy_from_slice(&credentials.static_key);
        rest[..payload.len()].copy_from_slice(&payload);
        let key: &'a [u8] = key;
        let rest: &'a [u8] = rest;
        Some(FoundCredential {
            local_static_privkey: key.try_into().ok()?,
            auth_credential: &rest[..payload.len()],
        })
    }
}

trait PumpChannel: ChannelIO {
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

/// Packet I/O for the THP pump; `recv_packet` returns `None` when `wait` elapses.
#[allow(async_fn_in_trait)]
trait PacketLink {
    async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()>;
    async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>>;
}

impl PacketLink for BleLink {
    async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()> {
        self.write(packet)
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))
    }

    async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>> {
        match time::timeout(wait, self.read()).await {
            Ok(Ok(packet)) => Ok(Some(packet)),
            Ok(Err(err)) => Err(BackendError::Transport(err.to_string())),
            Err(_) => Ok(None),
        }
    }
}

async fn flush<L: PacketLink, C: ChannelIO>(
    link: &mut L,
    channel: &mut Buffered<C>,
) -> BackendResult<()> {
    while channel.packet_out_ready() {
        let packet = channel.packet_out().map_err(thp_error)?;
        link.send_packet(&packet).await?;
    }
    Ok(())
}

fn can_retransmit(retry: Option<u8>) -> bool {
    retry.is_some_and(|r| r.saturating_add(1) < MAX_RETRANSMISSION_COUNT)
}

/// Sends pending packets and feeds incoming ones until `done` holds, retransmitting unacked messages.
async fn pump<L: PacketLink, C: PumpChannel>(
    link: &mut L,
    channel: &mut Buffered<C>,
    response_timeout: Duration,
    mut done: impl FnMut(&Buffered<C>, &PacketInResult) -> bool,
) -> BackendResult<()> {
    loop {
        flush(link, channel).await?;
        let retry = channel.retry_count();
        let wait = retry.map_or(response_timeout, |r| {
            Duration::from_millis(retransmit_after_ms(r).into())
        });
        let Some(packet) = link.recv_packet(wait).await? else {
            if !can_retransmit(retry) {
                return Err(BackendError::TransportTimeout);
            }
            channel.message_retransmit().map_err(thp_error)?;
            continue;
        };
        let result = channel.packet_in(&packet);
        match &result {
            PacketInResult::TransportError {
                error: TransportError::TransportBusy,
            } if can_retransmit(retry) => {
                let backoff = rand::random_range(0..MAX_BUSY_BACKOFF_MS);
                debug!("THP transport busy; resending in {backoff}ms");
                time::sleep(Duration::from_millis(backoff)).await;
                channel.message_retransmit().map_err(thp_error)?;
                continue;
            }
            PacketInResult::TransportError { error } => {
                return Err(backend_error_from_transport(*error));
            }
            PacketInResult::Failed { error } => return Err(thp_error(*error)),
            PacketInResult::Ignored { .. } => trace!("THP ignored packet"),
            _ => {}
        }
        if done(channel, &result) {
            return flush(link, channel).await;
        }
    }
}

/// Reads the next device message, acknowledging any ButtonRequest on the way.
async fn receive_message<L: PacketLink>(
    link: &mut L,
    channel: &mut Buffered<Channel<NoiseBackend>>,
    timeout: Duration,
) -> BackendResult<(u16, Vec<u8>)> {
    loop {
        pump(link, channel, timeout, |_, result| result.got_message()).await?;
        // trezor-thp queues the ACK when the message is consumed, so flush after message_out.
        let (_session, message_type, payload) = channel.message_out().map_err(thp_error)?;
        trace!(message_type, len = payload.len(), "THP receive");
        if message_type != MESSAGE_TYPE_BUTTON_REQUEST {
            flush(link, channel).await?;
            return Ok((message_type, payload));
        }
        debug!("THP ButtonRequest; sending ButtonAck");
        channel
            .message_in(SESSION_ID, MESSAGE_TYPE_BUTTON_ACK, &[])
            .map_err(thp_error)?;
    }
}

enum ThpChannel {
    Closed,
    Opening(Box<Buffered<ChannelOpen<SharedCredentials, NoiseBackend>>>),
    Open(Box<Buffered<Channel<NoiseBackend>>>),
}

pub struct BleBackend {
    inner: TransportBackend,
    device: DeviceInfo,
    handshake_timeout: Duration,
    channel: ThpChannel,
    credentials: SharedCredentials,
    nfc_secret: Option<[u8; 16]>,
}

impl BleBackend {
    pub fn new(link: BleLink, device: DeviceInfo) -> Self {
        Self {
            inner: TransportBackend::new(link),
            device,
            handshake_timeout: Duration::from_secs(10),
            channel: ThpChannel::Closed,
            credentials: SharedCredentials::default(),
            nfc_secret: None,
        }
    }

    pub fn from_session(session: BleSession) -> Self {
        let (device, link) = session.into_parts();
        Self::new(link, device)
    }

    pub fn link_mut(&mut self) -> &mut BleLink {
        self.inner.link_mut()
    }

    pub fn device_info(&self) -> &DeviceInfo {
        &self.device
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn set_handshake_timeout(&mut self, timeout: Duration) {
        self.handshake_timeout = timeout;
    }

    fn open_channel(&mut self) -> BackendResult<&mut Buffered<Channel<NoiseBackend>>> {
        match &mut self.channel {
            ThpChannel::Open(channel) => Ok(channel),
            _ => Err(BackendError::Transport(
                "THP channel is not established".into(),
            )),
        }
    }

    fn send(&mut self, message: &EncodedMessage) -> BackendResult<()> {
        trace!(
            message_type = message.message_type,
            len = message.payload.len(),
            "THP send"
        );
        self.open_channel()?
            .message_in(SESSION_ID, message.message_type, &message.payload)
            .map_err(thp_error)
    }

    async fn receive_raw(&mut self) -> BackendResult<(u16, Vec<u8>)> {
        let timeout = self.handshake_timeout;
        let link = self.inner.link_mut();
        let ThpChannel::Open(channel) = &mut self.channel else {
            return Err(BackendError::Transport(
                "THP channel is not established".into(),
            ));
        };
        receive_message(link, channel, timeout).await
    }

    async fn receive(&mut self) -> BackendResult<(u16, Vec<u8>)> {
        let (message_type, payload) = self.receive_raw().await?;
        if message_type == MESSAGE_TYPE_FAILURE {
            return Err(decode_failure_as_backend_error(&payload));
        }
        Ok((message_type, payload))
    }

    async fn request(&mut self, message: EncodedMessage) -> BackendResult<(u16, Vec<u8>)> {
        self.send(&message)?;
        self.receive().await
    }

    async fn call<T>(
        &mut self,
        message: Result<EncodedMessage, ProtoMappingError>,
        decode: impl FnOnce(u16, &[u8]) -> Result<T, ProtoMappingError>,
    ) -> BackendResult<T> {
        let (message_type, payload) = self.request(message.map_err(mapping_error)?).await?;
        decode(message_type, &payload).map_err(mapping_error)
    }

    async fn allocate_channel(&mut self, try_to_unlock: bool) -> BackendResult<()> {
        let timeout = self.handshake_timeout;
        let link = self.inner.link_mut();
        let mut mux = Buffered::new(Mux::<NoiseBackend>::new());
        mux.set_packet_len(link.mtu());
        mux.request_channel(try_to_unlock);
        pump(link, &mut mux, timeout, |_, result| result.got_channel()).await?;
        let open = mux
            .map(|mux| mux.complete(self.credentials.clone()))
            .map_err(thp_error)?;
        self.channel = ThpChannel::Opening(Box::new(open));
        Ok(())
    }

    async fn run_handshake(&mut self) -> BackendResult<HandshakeCompletionState> {
        let ThpChannel::Opening(mut open) =
            std::mem::replace(&mut self.channel, ThpChannel::Closed)
        else {
            return Err(BackendError::Transport(
                "THP handshake requires an allocated channel".into(),
            ));
        };
        let timeout = self.handshake_timeout;
        pump(self.inner.link_mut(), &mut open, timeout, |open, _| {
            open.handshake_done() || open.handshake_failed()
        })
        .await?;
        if open.handshake_failed() {
            return Err(BackendError::Transport("THP handshake failed".into()));
        }
        let channel = (*open).map(|open| open.complete()).map_err(thp_error)?;
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

    fn handshake_hash(&mut self) -> BackendResult<Vec<u8>> {
        Ok(self.open_channel()?.handshake_hash().to_vec())
    }

    fn end_pairing(&mut self) -> BackendResult<()> {
        self.open_channel()?.end_pairing();
        Ok(())
    }

    fn reset_channel(&mut self) {
        self.channel = ThpChannel::Closed;
        self.nfc_secret = None;
    }
}

mod backend_impl;
mod bitcoin;

#[cfg(test)]
mod tests;
