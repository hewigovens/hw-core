use std::convert::TryFrom;
use std::time::Duration;

use async_trait::async_trait;
use ble_transport::{BleBackend as TransportBackend, BleLink, BleSession, DeviceInfo};
use hex;
use prost::Message;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tokio::time;
use tracing::debug;

use crate::thp::backend::{BackendError, BackendResult, ThpBackend};
use crate::thp::crypto::curve25519::{
    derive_public_from_private, get_curve25519_key_pair, Curve25519KeyPair,
};
use crate::thp::crypto::pairing::{
    get_cpace_host_keys, get_shared_secret, handle_handshake_init, validate_code_entry_tag,
    validate_qr_code_tag, HandshakeInitInput, HandshakeInitResponse, PairingCryptoError,
};
use crate::thp::crypto::{aes256gcm_decrypt, aes256gcm_encrypt, get_iv_from_nonce};
use crate::thp::proto;
use crate::thp::proto_conversions::to_pairing_tag_response;
use crate::thp::proto_conversions::{
    decode_credential_response, decode_get_address_response, decode_get_public_key_response,
    decode_pairing_request_approved, decode_select_method_response, decode_tag_response,
    encode_code_entry_tag, encode_credential_request, encode_end_request,
    encode_get_address_request, encode_get_public_key_request, encode_nfc_tag,
    encode_pairing_request, encode_qr_tag, encode_select_method, EncodedMessage, ProtoMappingError,
};
use crate::thp::types::*;
use crate::thp::wire::{
    self, ParsedMessage, ThpWireState, WireError, WireResponse, MAGIC_CONTROL_ENCRYPTED,
    MAGIC_CREATE_CHANNEL_REQUEST, MAGIC_CREATE_CHANNEL_RESPONSE,
    MAGIC_HANDSHAKE_COMPLETION_REQUEST, MAGIC_HANDSHAKE_INIT_REQUEST,
};
use crate::thp::ThpTransport;
use sha2::{Digest, Sha256};

const MESSAGE_TYPE_SUCCESS: u16 = 5;
const MESSAGE_TYPE_CREATE_SESSION: u16 = 1000;
const MESSAGE_TYPE_BUTTON_REQUEST: u16 = proto::ThpMessageType::ButtonRequest as i32 as u16;
const MESSAGE_TYPE_BUTTON_ACK: u16 = proto::ThpMessageType::ButtonAck as i32 as u16;

pub struct BleBackend {
    inner: TransportBackend,
    device: DeviceInfo,
    transport: ThpTransport,
    handshake_timeout: Duration,
    state: ThpWireState,
    rx_buffer: Vec<u8>,
    continuation: Vec<u8>,
}

impl BleBackend {
    pub fn new(link: BleLink, device: DeviceInfo) -> Self {
        Self {
            inner: TransportBackend::new(link),
            device,
            transport: ThpTransport::new(),
            handshake_timeout: Duration::from_secs(10),
            state: ThpWireState::new(),
            rx_buffer: Vec::new(),
            continuation: Vec::new(),
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

    fn map_transport_error<E: std::fmt::Display>(&self, err: E) -> BackendError {
        BackendError::Transport(err.to_string())
    }

    fn map_wire_error(&self, err: WireError) -> BackendError {
        BackendError::Transport(err.to_string())
    }

    fn map_proto_error(&self, err: ProtoMappingError) -> BackendError {
        BackendError::Transport(err.to_string())
    }

    fn map_crypto_error(&self, err: PairingCryptoError) -> BackendError {
        BackendError::Transport(err.to_string())
    }

    async fn send_frame(&mut self, frame: Vec<u8>) -> BackendResult<()> {
        debug!(
            "BLE THP TX frame: magic=0x{:02x} len={}",
            frame.first().copied().unwrap_or(0),
            frame.len()
        );
        let mtu = {
            let link = self.inner.link_mut();
            link.mtu()
        };
        let chunks = chunk_v2_frame(&frame, mtu);

        for chunk in chunks {
            let write_future = {
                let link = self.inner.link_mut();
                link.write(&chunk)
            };

            if let Err(err) = write_future.await {
                return Err(self.map_transport_error(err));
            }
        }
        Ok(())
    }

    fn try_parse(&mut self) -> BackendResult<Option<ParsedMessage>> {
        trim_zero_padding(&mut self.rx_buffer);
        if self.rx_buffer.is_empty() {
            return Ok(None);
        }

        let expected_channel = if self.state.is_default_channel() {
            None
        } else {
            Some(self.state.channel())
        };

        match wire::decode_frame(&self.rx_buffer, expected_channel) {
            Ok(decoded) => {
                self.rx_buffer.drain(..decoded.consumed);
                trim_zero_padding(&mut self.rx_buffer);
                let parsed =
                    wire::parse_response(decoded.message).map_err(|e| self.map_wire_error(e))?;
                Ok(Some(parsed))
            }
            Err(WireError::ShortPacket) => Ok(None),
            Err(err) => Err(self.map_wire_error(err)),
        }
    }

    async fn read_next(&mut self) -> BackendResult<ParsedMessage> {
        loop {
            if let Some(mut parsed) = self.try_parse()? {
                match &mut parsed.response {
                    WireResponse::Ack => continue,
                    WireResponse::Continuation(chunk) => {
                        self.continuation.append(chunk);
                        continue;
                    }
                    WireResponse::Protobuf { payload } => {
                        if !self.continuation.is_empty() {
                            let mut merged = std::mem::take(&mut self.continuation);
                            merged.extend(payload.iter());
                            *payload = merged;
                        }
                        return Ok(parsed);
                    }
                    _ => {
                        self.continuation.clear();
                        if self.should_ack(&parsed.header) {
                            self.send_ack(&parsed.header).await?;
                        }
                        return Ok(parsed);
                    }
                }
            }

            let read_future = {
                let link = self.inner.link_mut();
                link.read()
            };

            let chunk = time::timeout(self.handshake_timeout, read_future)
                .await
                .map_err(|_| BackendError::Transport("timeout waiting for BLE response".into()))?
                .map_err(|e| self.map_transport_error(e))?;
            debug!(
                "BLE THP RX chunk: first=0x{:02x} len={}",
                chunk.first().copied().unwrap_or(0),
                chunk.len()
            );
            self.rx_buffer.extend_from_slice(&chunk);
        }
    }

    fn to_array<const N: usize>(&self, bytes: &[u8]) -> BackendResult<[u8; N]> {
        if bytes.len() != N {
            return Err(BackendError::Transport(format!(
                "expected {N} bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn host_key(&self) -> BackendResult<[u8; 32]> {
        self.state
            .host_key()
            .ok_or_else(|| BackendError::Transport("missing host encryption key".into()))
    }

    fn trezor_key(&self) -> BackendResult<[u8; 32]> {
        self.state
            .trezor_key()
            .ok_or_else(|| BackendError::Transport("missing device encryption key".into()))
    }

    fn encrypt_host_message(
        &mut self,
        message_type: u16,
        payload: &[u8],
    ) -> BackendResult<Vec<u8>> {
        let key = self.host_key()?;
        let session_id = self.state.session_id();
        let nonce = self.state.send_nonce();
        let iv = get_iv_from_nonce(nonce);

        let mut plaintext = Vec::with_capacity(1 + 2 + payload.len());
        plaintext.push(session_id);
        plaintext.extend_from_slice(&message_type.to_be_bytes());
        plaintext.extend_from_slice(payload);

        let (cipher, tag) = aes256gcm_encrypt(&key, &iv, &[], &plaintext)
            .map_err(|_| BackendError::Transport("failed to encrypt THP payload".into()))?;

        let mut ciphertext = cipher;
        ciphertext.extend_from_slice(&tag);

        let frame =
            wire::encode_protobuf_request(self.state.channel(), self.state.send_bit(), &ciphertext);
        Ok(frame)
    }

    fn decrypt_device_message(&mut self, payload: &[u8]) -> BackendResult<(u16, Vec<u8>)> {
        if payload.len() < 1 + 2 + 16 {
            return Err(BackendError::Transport(
                "device payload too short for THP message".into(),
            ));
        }

        let key = self.trezor_key()?;
        let nonce = self.state.recv_nonce();
        let iv = get_iv_from_nonce(nonce);

        let tag_offset = payload.len() - 16;
        let ciphertext = &payload[..tag_offset];
        let tag = &payload[tag_offset..];
        let tag_array = self.to_array::<16>(tag)?;

        let plaintext = aes256gcm_decrypt(&key, &iv, &[], ciphertext, &tag_array).map_err(|e| {
            BackendError::Transport(format!("failed to decrypt device payload: {e}"))
        })?;

        if plaintext.len() < 3 {
            return Err(BackendError::Transport(
                "decrypted payload too short".into(),
            ));
        }

        let session_id = plaintext[0];
        if session_id != self.state.session_id() {
            debug!(
                expected = self.state.session_id(),
                received = session_id,
                "BLE THP response session id differs from local state"
            );
        }

        let message_type = u16::from_be_bytes([plaintext[1], plaintext[2]]);
        Ok((message_type, plaintext[3..].to_vec()))
    }

    async fn send_ack(&mut self, _header: &wire::WireHeader) -> BackendResult<()> {
        let ack_bit = self.state.recv_ack_bit();
        let frame = wire::encode_ack(self.state.channel(), ack_bit);
        self.send_frame(frame).await?;
        Ok(())
    }

    async fn send_encrypted_request(&mut self, encoded: EncodedMessage) -> BackendResult<()> {
        debug!(
            "BLE THP TX encrypted message_type={} ({}) payload_len={}",
            encoded.message_type,
            thp_message_name(encoded.message_type),
            encoded.payload.len()
        );
        let frame = self.encrypt_host_message(encoded.message_type, &encoded.payload)?;
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_CONTROL_ENCRYPTED);
        Ok(())
    }

    async fn send_button_ack(&mut self) -> BackendResult<()> {
        debug!("BLE THP sending ButtonAck");
        self.send_encrypted_request(EncodedMessage {
            message_type: MESSAGE_TYPE_BUTTON_ACK,
            payload: Vec::new(),
        })
        .await
    }

    async fn parse_encrypted_response<T>(
        &mut self,
        mut parsed: ParsedMessage,
        decoder: impl Fn(u16, &[u8]) -> Result<T, ProtoMappingError>,
    ) -> BackendResult<T> {
        loop {
            if self.should_ack(&parsed.header) {
                self.send_ack(&parsed.header).await?;
            }

            let (message_type, payload) = match parsed.response {
                WireResponse::Protobuf { payload } => {
                    let res = self.decrypt_device_message(&payload)?;
                    self.state.on_receive(parsed.header.magic);
                    res
                }
                WireResponse::Error(code) => {
                    return Err(BackendError::Device(format!(
                        "device returned error code {code}"
                    )))
                }
                other => {
                    return Err(BackendError::Transport(format!(
                        "unexpected response type {:?}",
                        other
                    )))
                }
            };

            debug!(
                "BLE THP RX encrypted message_type={} ({}) payload_len={}",
                message_type,
                thp_message_name(message_type),
                payload.len()
            );

            if message_type == MESSAGE_TYPE_BUTTON_REQUEST {
                debug!("BLE THP received ButtonRequest; acknowledging to continue workflow");
                self.send_button_ack().await?;
                parsed = self.read_next().await?;
                continue;
            }

            let result = decoder(message_type, &payload).map_err(|e| self.map_proto_error(e))?;
            self.state.set_expected_responses(Vec::new());
            return Ok(result);
        }
    }

    fn should_ack(&self, header: &wire::WireHeader) -> bool {
        !matches!(
            header.magic,
            MAGIC_CREATE_CHANNEL_RESPONSE | wire::MAGIC_READ_ACK
        )
    }
}

fn thp_message_name(message_type: u16) -> String {
    match proto::ThpMessageType::try_from(message_type as i32) {
        Ok(kind) => format!("{kind:?}"),
        Err(_) => format!("Unknown({message_type})"),
    }
}

fn chunk_v2_frame(frame: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    if mtu == 0 {
        return vec![frame.to_vec()];
    }

    if frame.len() <= mtu {
        let mut chunk = vec![0u8; mtu];
        chunk[..frame.len()].copy_from_slice(frame);
        return vec![chunk];
    }

    let mut chunks = Vec::new();
    chunks.push(frame[..mtu].to_vec());

    let continuation_header = if frame.len() >= 3 {
        [wire::MAGIC_CONTINUATION, frame[1], frame[2]]
    } else {
        [wire::MAGIC_CONTINUATION, 0, 0]
    };

    let mut position = mtu;
    while position < frame.len() {
        let payload_budget = mtu.saturating_sub(continuation_header.len());
        if payload_budget == 0 {
            break;
        }
        let end = (position + payload_budget).min(frame.len());
        let payload = &frame[position..end];

        let mut chunk = vec![0u8; mtu];
        chunk[..continuation_header.len()].copy_from_slice(&continuation_header);
        let payload_end = continuation_header.len() + payload.len();
        chunk[continuation_header.len()..payload_end].copy_from_slice(payload);
        chunks.push(chunk);
        position = end;
    }

    chunks
}

fn trim_zero_padding(buffer: &mut Vec<u8>) {
    let leading_zeros = buffer.iter().take_while(|b| **b == 0).count();
    if leading_zeros > 0 {
        buffer.drain(..leading_zeros);
    }
}

#[async_trait]
impl ThpBackend for BleBackend {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        debug!(
            "THP create_channel start: nonce={}",
            hex::encode(request.nonce)
        );
        let frame = wire::encode_create_channel_request(&request.nonce);
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_CREATE_CHANNEL_REQUEST);

        let parsed = self.read_next().await?;
        let response = match parsed.response {
            WireResponse::CreateChannel {
                nonce,
                channel,
                properties,
                handshake_hash,
            } => {
                if nonce != request.nonce {
                    return Err(BackendError::Transport(
                        "nonce mismatch in THP create channel".into(),
                    ));
                }
                self.state.on_receive(parsed.header.magic);
                self.state.set_channel(channel);
                self.state.set_handshake_hash(handshake_hash);
                debug!(
                    "THP create_channel ok: channel=0x{:04x} methods={:?} protocol={}.{} model={} variant={}",
                    channel,
                    properties.pairing_methods,
                    properties.protocol_version_major,
                    properties.protocol_version_minor,
                    properties.internal_model,
                    properties.model_variant
                );
                CreateChannelResponse {
                    nonce,
                    channel,
                    handshake_hash: handshake_hash.to_vec(),
                    properties,
                }
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )))
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to create_channel: {:?}",
                    other
                )))
            }
        };

        Ok(response)
    }

    async fn handshake_init(
        &mut self,
        request: HandshakeInitRequest,
    ) -> BackendResult<HandshakeInitOutcome> {
        let handshake_hash = self
            .state
            .handshake_hash()
            .ok_or_else(|| BackendError::Transport("missing handshake hash".into()))?;

        let mut rng = StdRng::from_rng(&mut rand::rng());

        let (host_static_private, host_static_public, host_static_vec) =
            if let Some(ref key) = request.static_key {
                let array = self.to_array::<32>(key)?;
                let public = derive_public_from_private(&array);
                (array, public, key.clone())
            } else {
                let Curve25519KeyPair {
                    private_key,
                    public_key,
                } = get_curve25519_key_pair(&mut rng);
                (private_key, public_key, private_key.to_vec())
            };

        let Curve25519KeyPair {
            private_key: host_ephemeral_private,
            public_key: host_ephemeral_public,
        } = get_curve25519_key_pair(&mut rng);

        let frame = wire::encode_handshake_init_request(
            self.state.channel(),
            self.state.send_bit(),
            &host_ephemeral_public,
            request.try_to_unlock,
        );
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_HANDSHAKE_INIT_REQUEST);

        let parsed = self.read_next().await?;
        let (trezor_ephemeral_pubkey, trezor_encrypted_static_pubkey, tag) = match parsed.response {
            WireResponse::HandshakeInit {
                trezor_ephemeral_pubkey,
                trezor_encrypted_static_pubkey,
                tag,
            } => {
                self.state.on_receive(parsed.header.magic);
                self.state.set_expected_responses(Vec::new());
                (trezor_ephemeral_pubkey, trezor_encrypted_static_pubkey, tag)
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )))
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to handshake init: {:?}",
                    other
                )))
            }
        };

        let encode_handshake_payload = |credential: Option<&str>| -> Vec<u8> {
            let host_pairing_credential = credential.and_then(|c| hex::decode(c).ok());
            let message = proto::ThpHandshakeCompletionReqNoisePayload {
                host_pairing_credential,
            };
            let mut buf = Vec::new();
            message.encode(&mut buf).expect("encode handshake payload");
            buf
        };

        let handshake_response = HandshakeInitResponse {
            trezor_ephemeral_pubkey,
            trezor_encrypted_static_pubkey: &trezor_encrypted_static_pubkey,
            tag,
        };

        let handshake_result = handle_handshake_init(HandshakeInitInput {
            handshake_hash,
            send_nonce: self.state.send_nonce(),
            recv_nonce: self.state.recv_nonce(),
            host_static_private,
            host_static_public,
            host_ephemeral_private,
            host_ephemeral_public,
            try_to_unlock: request.try_to_unlock,
            known_credentials: &request.known_credentials,
            response: handshake_response,
            encode_handshake_payload: &encode_handshake_payload,
        })
        .map_err(|e| self.map_crypto_error(e))?;

        self.state
            .set_keys(handshake_result.host_key, handshake_result.trezor_key);
        self.state
            .set_handshake_hash(handshake_result.handshake_hash);

        let outcome = HandshakeInitOutcome {
            host_encrypted_static_pubkey: handshake_result.host_encrypted_static_pubkey,
            encrypted_payload: handshake_result.encrypted_payload,
            trezor_encrypted_static_pubkey: handshake_result.trezor_encrypted_static_pubkey,
            handshake_hash: handshake_result.handshake_hash.to_vec(),
            host_key: handshake_result.host_key.to_vec(),
            trezor_key: handshake_result.trezor_key.to_vec(),
            host_static_key: host_static_vec,
            host_static_public_key: host_static_public.to_vec(),
            pairing_methods: request.pairing_methods,
            credentials: handshake_result.credentials.clone(),
            selected_credential: handshake_result.selected_credential.clone(),
            nfc_data: None,
            handshake_commitment: None,
            trezor_cpace_public_key: None,
            code_entry_challenge: None,
        };

        Ok(outcome)
    }

    async fn handshake_complete(
        &mut self,
        request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse> {
        let frame = wire::encode_handshake_completion_request(
            self.state.channel(),
            self.state.send_bit(),
            &request.host_pubkey,
            &request.encrypted_payload,
        );
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_HANDSHAKE_COMPLETION_REQUEST);

        let parsed = self.read_next().await?;
        let state = match parsed.response {
            WireResponse::HandshakeCompletion {
                encrypted_state,
                tag,
            } => {
                self.state.on_receive(parsed.header.magic);
                self.state.set_expected_responses(Vec::new());

                // Handshake completion response is AES-GCM encrypted with key_response,
                // nonce 0, empty associated data and a single-byte plaintext state.
                let key = self.trezor_key()?;
                let iv = [0u8; 12];
                let plaintext = aes256gcm_decrypt(&key, &iv, &[], &[encrypted_state], &tag)
                    .map_err(|_| {
                        BackendError::Transport(
                            "failed to decrypt handshake completion state".into(),
                        )
                    })?;
                if plaintext.len() != 1 {
                    return Err(BackendError::Transport(format!(
                        "invalid decrypted handshake completion state length {}",
                        plaintext.len()
                    )));
                }
                plaintext[0]
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )))
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to handshake completion: {:?}",
                    other
                )))
            }
        };

        let completion_state = match state {
            0 => HandshakeCompletionState::RequiresPairing,
            1 => HandshakeCompletionState::Paired,
            2 => HandshakeCompletionState::AutoPaired,
            other => {
                return Err(BackendError::Transport(format!(
                    "unknown handshake completion state {other}"
                )))
            }
        };

        Ok(HandshakeCompletionResponse {
            state: completion_state,
        })
    }

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        let encoded = encode_pairing_request(&request).map_err(|e| self.map_proto_error(e))?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type != proto::ThpMessageType::ThpPairingRequestApproved as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_pairing_request_approved(payload)
            })
            .await?;

        Ok(response)
    }

    async fn select_pairing_method(
        &mut self,
        request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        let encoded = encode_select_method(&request).map_err(|e| self.map_proto_error(e))?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                let message_type_enum = proto::ThpMessageType::try_from(message_type as i32)
                    .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                decode_select_method_response(message_type_enum, payload)
            })
            .await?;

        Ok(response)
    }

    async fn send_pairing_tag(
        &mut self,
        request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        match request {
            PairingTagRequest::QrCode {
                handshake_hash,
                tag,
            } => {
                let tag_bytes = hex::decode(&tag)
                    .map_err(|_| BackendError::Transport("invalid QR tag hex".into()))?;
                let mut hasher = Sha256::new();
                hasher.update(&handshake_hash);
                hasher.update(tag_bytes);
                let hashed = hasher.finalize();
                let hashed_hex = hex::encode(hashed);

                let encoded = encode_qr_tag(&hashed_hex).map_err(|e| self.map_proto_error(e))?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let response = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        let message_type_enum =
                            proto::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        decode_tag_response(message_type_enum, payload)
                    })
                    .await?;

                validate_qr_code_tag(&handshake_hash, &tag, &hex::encode(&response.secret))
                    .map_err(|e| self.map_crypto_error(e))?;

                Ok(to_pairing_tag_response(response))
            }
            PairingTagRequest::Nfc {
                handshake_hash,
                tag,
            } => {
                let tag_bytes = hex::decode(&tag)
                    .map_err(|_| BackendError::Transport("invalid NFC tag hex".into()))?;
                let mut hasher = Sha256::new();
                hasher.update([proto::ThpPairingMethod::Nfc as u8]);
                hasher.update(&handshake_hash);
                hasher.update(&tag_bytes);
                let hashed = hasher.finalize();
                let hashed_hex = hex::encode(hashed);

                let encoded = encode_nfc_tag(&hashed_hex).map_err(|e| self.map_proto_error(e))?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let response = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        let message_type_enum =
                            proto::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        decode_tag_response(message_type_enum, payload)
                    })
                    .await?;

                // Validation requires stored NFC secret; not available here, so defer to workflow.
                Ok(to_pairing_tag_response(response))
            }
            PairingTagRequest::CodeEntry {
                code,
                handshake_hash,
                commitment,
                challenge,
                trezor_cpace_public_key,
                ..
            } => {
                if code.len() != 6 {
                    return Err(BackendError::Transport(
                        "code entry must be 6 digits".into(),
                    ));
                }

                let mut rng = StdRng::from_rng(&mut rand::rng());
                let keys = get_cpace_host_keys(code.as_bytes(), &handshake_hash, &mut rng);
                let trezor_key = trezor_cpace_public_key.as_ref().ok_or_else(|| {
                    BackendError::Transport("missing trezor cpace public key".into())
                })?;
                let trezor_key = self.to_array::<32>(trezor_key)?;
                let shared_secret = get_shared_secret(&trezor_key, &keys.private_key);

                let encoded = encode_code_entry_tag(&keys.public_key, &shared_secret)
                    .map_err(|e| self.map_proto_error(e))?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let response = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        let message_type_enum =
                            proto::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        decode_tag_response(message_type_enum, payload)
                    })
                    .await?;

                validate_code_entry_tag(
                    &handshake_hash,
                    commitment.as_ref().ok_or_else(|| {
                        BackendError::Transport("missing handshake commitment".into())
                    })?,
                    challenge.as_ref().ok_or_else(|| {
                        BackendError::Transport("missing code entry challenge".into())
                    })?,
                    &code,
                    &hex::encode(&response.secret),
                )
                .map_err(|e| self.map_crypto_error(e))?;

                Ok(to_pairing_tag_response(response))
            }
        }
    }

    async fn credential_request(
        &mut self,
        request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        let encoded = encode_credential_request(&request).map_err(|e| self.map_proto_error(e))?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type != proto::ThpMessageType::ThpCredentialResponse as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_credential_response(payload)
            })
            .await?;

        Ok(response)
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        let encoded = encode_end_request().map_err(|e| self.map_proto_error(e))?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        self.parse_encrypted_response(parsed, |message_type, payload| {
            if message_type != proto::ThpMessageType::ThpEndResponse as i32 as u16 {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            proto::ThpEndResponse::decode(payload).map_err(ProtoMappingError::from)?;
            Ok(())
        })
        .await?;

        Ok(())
    }

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        let message = proto::ThpCreateNewSession {
            passphrase: request.passphrase.clone(),
            on_device: request.on_device.then_some(true),
            derive_cardano: request.derive_cardano.then_some(true),
        };

        let mut payload = Vec::new();
        message
            .encode(&mut payload)
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        let encoded = EncodedMessage {
            message_type: MESSAGE_TYPE_CREATE_SESSION,
            payload,
        };
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        self.parse_encrypted_response(parsed, |message_type, _| {
            if message_type != MESSAGE_TYPE_SUCCESS {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            Ok(())
        })
        .await?;

        Ok(CreateSessionResponse)
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        let encoded = encode_get_address_request(&request).map_err(|e| self.map_proto_error(e))?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let mut response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                decode_get_address_response(request.chain, message_type, payload)
            })
            .await?;

        if request.include_public_key {
            let encoded = encode_get_public_key_request(
                request.chain,
                &request.address_n,
                request.show_display,
            )
            .map_err(|e| self.map_proto_error(e))?;
            self.send_encrypted_request(encoded).await?;

            let parsed = self.read_next().await?;
            let public_key = self
                .parse_encrypted_response(parsed, |message_type, payload| {
                    decode_get_public_key_response(request.chain, message_type, payload)
                })
                .await?;
            response.public_key = Some(public_key);
        }

        Ok(response)
    }

    async fn abort(&mut self) -> BackendResult<()> {
        self.transport.reset();
        self.inner
            .abort()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))
    }
}
