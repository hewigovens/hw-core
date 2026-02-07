use std::convert::TryInto;

use crc32fast::Hasher;
use thiserror::Error;

use super::proto_conversions::{decode_device_properties, ProtoMappingError};
use super::types::ThpProperties;

pub const MAGIC_CREATE_CHANNEL_REQUEST: u8 = 0x40;
pub const MAGIC_CREATE_CHANNEL_RESPONSE: u8 = 0x41;
pub const MAGIC_HANDSHAKE_INIT_REQUEST: u8 = 0x00;
pub const MAGIC_HANDSHAKE_INIT_RESPONSE: u8 = 0x01;
pub const MAGIC_HANDSHAKE_COMPLETION_REQUEST: u8 = 0x02;
pub const MAGIC_HANDSHAKE_COMPLETION_RESPONSE: u8 = 0x03;
pub const MAGIC_CONTROL_ENCRYPTED: u8 = 0x04;
pub const MAGIC_CONTROL_DECRYPTED: u8 = 0x05;
pub const MAGIC_ERROR: u8 = 0x42;
pub const MAGIC_READ_ACK: u8 = 0x20;
pub const MAGIC_CONTINUATION: u8 = 0x80;

const THP_CREATE_CHANNEL_REQUEST: u8 = MAGIC_CREATE_CHANNEL_REQUEST;
const THP_CREATE_CHANNEL_RESPONSE: u8 = MAGIC_CREATE_CHANNEL_RESPONSE;
const THP_HANDSHAKE_INIT_REQUEST: u8 = MAGIC_HANDSHAKE_INIT_REQUEST;
const THP_HANDSHAKE_INIT_RESPONSE: u8 = MAGIC_HANDSHAKE_INIT_RESPONSE;
const THP_HANDSHAKE_COMPLETION_REQUEST: u8 = MAGIC_HANDSHAKE_COMPLETION_REQUEST;
const THP_HANDSHAKE_COMPLETION_RESPONSE: u8 = MAGIC_HANDSHAKE_COMPLETION_RESPONSE;
const THP_CONTROL_BYTE_ENCRYPTED: u8 = MAGIC_CONTROL_ENCRYPTED;
const THP_CONTROL_BYTE_DECRYPTED: u8 = MAGIC_CONTROL_DECRYPTED;
const THP_ERROR_HEADER_BYTE: u8 = MAGIC_ERROR;
const THP_READ_ACK_HEADER_BYTE: u8 = MAGIC_READ_ACK;
const THP_CONTINUATION_PACKET: u8 = MAGIC_CONTINUATION;

const ACK_BIT: u8 = 1 << 3;
const SEQ_BIT: u8 = 1 << 4;

const CRC_LENGTH: usize = 4;
const DEFAULT_CHANNEL: u16 = 0xffff;

fn is_handshake_magic(magic: u8) -> bool {
    matches!(
        magic,
        THP_HANDSHAKE_INIT_REQUEST
            | THP_HANDSHAKE_INIT_RESPONSE
            | THP_HANDSHAKE_COMPLETION_REQUEST
            | THP_HANDSHAKE_COMPLETION_RESPONSE
    )
}

fn should_toggle_sync(magic: u8) -> bool {
    !matches!(
        magic,
        THP_CREATE_CHANNEL_REQUEST | THP_CREATE_CHANNEL_RESPONSE | THP_READ_ACK_HEADER_BYTE
    )
}

fn should_increment_nonce(magic: u8) -> bool {
    should_toggle_sync(magic) && !is_handshake_magic(magic)
}

fn default_expected_responses(magic: u8) -> Vec<u8> {
    match magic {
        THP_CREATE_CHANNEL_REQUEST => vec![THP_CREATE_CHANNEL_RESPONSE],
        THP_HANDSHAKE_INIT_REQUEST => vec![THP_HANDSHAKE_INIT_RESPONSE, THP_CONTINUATION_PACKET],
        THP_HANDSHAKE_COMPLETION_REQUEST => {
            vec![THP_HANDSHAKE_COMPLETION_RESPONSE, THP_CONTINUATION_PACKET]
        }
        THP_CONTROL_BYTE_ENCRYPTED => vec![THP_CONTROL_BYTE_ENCRYPTED, THP_CONTINUATION_PACKET],
        THP_CONTROL_BYTE_DECRYPTED => vec![THP_CONTROL_BYTE_DECRYPTED, THP_CONTINUATION_PACKET],
        _ => Vec::new(),
    }
}

#[derive(Debug, Clone)]
pub struct ThpWireState {
    channel: u16,
    send_bit: u8,
    recv_bit: u8,
    send_ack_bit: u8,
    recv_ack_bit: u8,
    send_nonce: u64,
    recv_nonce: u64,
    session_id: u8,
    expected_responses: Vec<u8>,
    handshake_hash: Option<[u8; 32]>,
    host_key: Option<[u8; 32]>,
    trezor_key: Option<[u8; 32]>,
}

impl Default for ThpWireState {
    fn default() -> Self {
        Self {
            channel: DEFAULT_CHANNEL,
            send_bit: 0,
            recv_bit: 0,
            send_ack_bit: 0,
            recv_ack_bit: 0,
            send_nonce: 0,
            recv_nonce: 1,
            session_id: 0,
            expected_responses: Vec::new(),
            handshake_hash: None,
            host_key: None,
            trezor_key: None,
        }
    }
}

impl ThpWireState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn channel(&self) -> u16 {
        self.channel
    }

    pub fn set_channel(&mut self, channel: u16) {
        self.channel = channel;
    }

    pub fn is_default_channel(&self) -> bool {
        self.channel == DEFAULT_CHANNEL
    }

    pub fn expected_responses(&self) -> &[u8] {
        &self.expected_responses
    }

    pub fn set_expected_responses(&mut self, expected: Vec<u8>) {
        self.expected_responses = expected;
    }

    pub fn send_bit(&self) -> u8 {
        self.send_bit
    }

    pub fn send_ack_bit(&self) -> u8 {
        self.send_ack_bit
    }

    pub fn recv_bit(&self) -> u8 {
        self.recv_bit
    }

    pub fn recv_ack_bit(&self) -> u8 {
        self.recv_ack_bit
    }

    pub fn send_nonce(&self) -> u64 {
        self.send_nonce
    }

    pub fn recv_nonce(&self) -> u64 {
        self.recv_nonce
    }

    pub fn session_id(&self) -> u8 {
        self.session_id
    }

    pub fn next_session_id(&mut self) -> u8 {
        let next = self.session_id.wrapping_add(1);
        self.session_id = if next == 0 { 1 } else { next };
        self.session_id
    }

    pub fn set_handshake_hash(&mut self, hash: [u8; 32]) {
        self.handshake_hash = Some(hash);
    }

    pub fn handshake_hash(&self) -> Option<[u8; 32]> {
        self.handshake_hash
    }

    pub fn set_keys(&mut self, host_key: [u8; 32], trezor_key: [u8; 32]) {
        self.host_key = Some(host_key);
        self.trezor_key = Some(trezor_key);
    }

    pub fn host_key(&self) -> Option<[u8; 32]> {
        self.host_key
    }

    pub fn trezor_key(&self) -> Option<[u8; 32]> {
        self.trezor_key
    }

    pub fn on_send(&mut self, magic: u8) {
        if should_toggle_sync(magic) {
            self.send_ack_bit ^= 1;
            self.send_bit ^= 1;
        }
        if should_increment_nonce(magic) {
            self.send_nonce = self.send_nonce.wrapping_add(1);
        }
        self.expected_responses = default_expected_responses(magic);
    }

    pub fn on_receive(&mut self, magic: u8) {
        if should_toggle_sync(magic) {
            self.recv_ack_bit ^= 1;
            self.recv_bit ^= 1;
        }
        if should_increment_nonce(magic) {
            self.recv_nonce = self.recv_nonce.wrapping_add(1);
        }
    }
}

fn crc32(bytes: &[u8]) -> [u8; 4] {
    let mut hasher = Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_be_bytes()
}

fn add_sequence_bit(value: u8, seq_bit: u8) -> u8 {
    if seq_bit == 0 {
        value & !SEQ_BIT
    } else {
        value | SEQ_BIT
    }
}

fn add_ack_bit(value: u8, ack_bit: u8) -> u8 {
    if ack_bit == 0 {
        value & !ACK_BIT
    } else {
        value | ACK_BIT
    }
}

fn clear_control_bits(value: u8) -> u8 {
    value & !ACK_BIT & !SEQ_BIT
}

#[derive(Debug, Clone)]
pub struct WireHeader {
    pub raw_magic: u8,
    pub magic: u8,
    pub ack_bit: u8,
    pub seq_bit: u8,
    pub channel: u16,
}

impl WireHeader {
    fn new(magic: u8, channel: u16, ack_bit: u8, seq_bit: u8) -> Self {
        let mut raw = magic;
        raw = add_ack_bit(raw, ack_bit);
        raw = add_sequence_bit(raw, seq_bit);
        Self {
            raw_magic: raw,
            magic,
            ack_bit,
            seq_bit,
            channel,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WireMessage {
    pub header: WireHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("packet too short")]
    ShortPacket,
    #[error("crc mismatch")]
    CrcMismatch,
    #[error("unexpected channel: expected {expected:#06x}, got {actual:#06x}")]
    UnexpectedChannel { expected: u16, actual: u16 },
    #[error("unexpected message magic 0x{0:02x}")]
    UnexpectedMagic(u8),
    #[error("prost decode error: {0}")]
    Prost(#[from] prost::DecodeError),
    #[error("proto mapping error: {0}")]
    Mapping(#[from] ProtoMappingError),
}

#[derive(Debug)]
pub enum WireResponse {
    CreateChannel {
        nonce: [u8; 8],
        channel: u16,
        properties: ThpProperties,
        handshake_hash: [u8; 32],
    },
    HandshakeInit {
        trezor_ephemeral_pubkey: [u8; 32],
        trezor_encrypted_static_pubkey: Vec<u8>,
        tag: [u8; 16],
    },
    HandshakeCompletion {
        encrypted_state: u8,
        tag: [u8; 16],
    },
    Protobuf {
        payload: Vec<u8>,
    },
    Ack,
    Continuation(Vec<u8>),
    Error(u8),
}

fn encode_frame(header: WireHeader, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 2 + 2 + payload.len() + CRC_LENGTH);
    bytes.push(header.raw_magic);
    bytes.extend_from_slice(&header.channel.to_be_bytes());
    let len = (payload.len() + CRC_LENGTH) as u16;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(payload);
    let crc = crc32(&bytes);
    bytes.extend_from_slice(&crc);
    bytes
}

pub fn encode_create_channel_request(nonce: &[u8; 8]) -> Vec<u8> {
    let header = WireHeader::new(THP_CREATE_CHANNEL_REQUEST, DEFAULT_CHANNEL, 0, 0);
    encode_frame(header, nonce)
}

pub struct DecodedFrame {
    pub message: WireMessage,
    pub consumed: usize,
}

pub fn decode_frame(data: &[u8], expected_channel: Option<u16>) -> Result<DecodedFrame, WireError> {
    if data.len() < 1 + 2 + 2 + CRC_LENGTH {
        return Err(WireError::ShortPacket);
    }

    let raw_magic = data[0];
    let channel = u16::from_be_bytes([data[1], data[2]]);
    if let Some(expected) = expected_channel {
        if channel != expected {
            return Err(WireError::UnexpectedChannel {
                expected,
                actual: channel,
            });
        }
    }
    let length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if length < CRC_LENGTH {
        return Err(WireError::ShortPacket);
    }
    if data.len() < 5 + length {
        return Err(WireError::ShortPacket);
    }
    let payload_end = 5 + length - CRC_LENGTH;
    let payload = data[5..payload_end].to_vec();
    let crc = &data[payload_end..payload_end + CRC_LENGTH];
    let mut computed = Hasher::new();
    computed.update(&data[..payload_end]);
    if computed.finalize().to_be_bytes() != crc {
        return Err(WireError::CrcMismatch);
    }
    let ack_bit = if raw_magic & ACK_BIT > 0 { 1 } else { 0 };
    let seq_bit = if raw_magic & SEQ_BIT > 0 { 1 } else { 0 };
    let magic = clear_control_bits(raw_magic);
    let header = WireHeader {
        raw_magic,
        magic,
        ack_bit,
        seq_bit,
        channel,
    };
    Ok(DecodedFrame {
        message: WireMessage { header, payload },
        consumed: payload_end + CRC_LENGTH,
    })
}

pub struct ParsedMessage {
    pub header: WireHeader,
    pub response: WireResponse,
}

pub fn parse_response(message: WireMessage) -> Result<ParsedMessage, WireError> {
    let header = message.header.clone();
    let response = match message.header.magic {
        THP_CREATE_CHANNEL_RESPONSE => {
            if message.payload.len() < 8 + 2 {
                return Err(WireError::ShortPacket);
            }
            let nonce: [u8; 8] = message.payload[0..8].try_into().unwrap();
            let channel = u16::from_be_bytes(message.payload[8..10].try_into().unwrap());
            let props_buf = &message.payload[10..];
            let properties = decode_device_properties(props_buf)?;
            let handshake_hash = super::crypto::pairing::get_handshake_hash(props_buf);
            WireResponse::CreateChannel {
                nonce,
                channel,
                properties: ThpProperties {
                    internal_model: properties.internal_model,
                    model_variant: properties.model_variant,
                    protocol_version_major: properties.protocol_version_major,
                    protocol_version_minor: properties.protocol_version_minor,
                    pairing_methods: properties.pairing_methods,
                },
                handshake_hash,
            }
        }
        THP_HANDSHAKE_INIT_RESPONSE => {
            if message.payload.len() < 32 + 48 + 16 {
                return Err(WireError::ShortPacket);
            }
            let trezor_ephemeral_pubkey = message.payload[0..32]
                .try_into()
                .expect("slice length checked");
            let trezor_encrypted_static_pubkey = message.payload[32..32 + 48].to_vec();
            let tag = message.payload[32 + 48..32 + 48 + 16]
                .try_into()
                .expect("slice length checked");
            WireResponse::HandshakeInit {
                trezor_ephemeral_pubkey,
                trezor_encrypted_static_pubkey,
                tag,
            }
        }
        THP_HANDSHAKE_COMPLETION_RESPONSE => {
            if message.payload.len() < 1 + 16 {
                return Err(WireError::ShortPacket);
            }
            let tag = message.payload[1..1 + 16]
                .try_into()
                .expect("slice length checked");
            WireResponse::HandshakeCompletion {
                encrypted_state: message.payload[0],
                tag,
            }
        }
        THP_CONTROL_BYTE_ENCRYPTED | THP_CONTROL_BYTE_DECRYPTED => {
            if message.payload.len() < 17 {
                return Err(WireError::ShortPacket);
            }
            WireResponse::Protobuf {
                payload: message.payload,
            }
        }
        THP_READ_ACK_HEADER_BYTE => WireResponse::Ack,
        THP_CONTINUATION_PACKET => WireResponse::Continuation(message.payload),
        THP_ERROR_HEADER_BYTE => {
            let code = message.payload.first().copied().unwrap_or_default();
            WireResponse::Error(code)
        }
        other => return Err(WireError::UnexpectedMagic(other)),
    };
    Ok(ParsedMessage { header, response })
}

pub fn encode_handshake_init_request(
    channel: u16,
    send_bit: u8,
    host_ephemeral_pubkey: &[u8; 32],
    try_to_unlock: bool,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    payload.extend_from_slice(host_ephemeral_pubkey);
    payload.push(try_to_unlock as u8);
    let header = WireHeader::new(THP_HANDSHAKE_INIT_REQUEST, channel, 0, send_bit);
    encode_frame(header, &payload)
}

pub fn encode_handshake_completion_request(
    channel: u16,
    send_bit: u8,
    host_encrypted_static_pubkey: &[u8],
    encrypted_payload: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(host_encrypted_static_pubkey);
    payload.extend_from_slice(encrypted_payload);
    let header = WireHeader::new(THP_HANDSHAKE_COMPLETION_REQUEST, channel, 0, send_bit);
    encode_frame(header, &payload)
}

pub fn encode_protobuf_request(channel: u16, send_bit: u8, payload: &[u8]) -> Vec<u8> {
    let header = WireHeader::new(THP_CONTROL_BYTE_ENCRYPTED, channel, 0, send_bit);
    encode_frame(header, payload)
}

pub fn encode_ack(channel: u16, ack_bit: u8) -> Vec<u8> {
    let header = WireHeader::new(THP_READ_ACK_HEADER_BYTE, channel, ack_bit, 0);
    encode_frame(header, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::crypto::pairing::get_handshake_hash;
    use crate::thp::proto;
    use hex::encode as hex_encode;
    use prost::Message;

    #[test]
    fn create_channel_response_roundtrip() {
        let nonce = [0xAAu8; 8];
        let channel = 0x1234u16;
        let props = proto::ThpDeviceProperties {
            internal_model: "T2B1".into(),
            model_variant: Some(1),
            protocol_version_major: 1,
            protocol_version_minor: 2,
            pairing_methods: vec![proto::ThpPairingMethod::QrCode as i32],
        };
        let mut props_buf = Vec::new();
        props.encode(&mut props_buf).unwrap();

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&channel.to_be_bytes());
        payload.extend_from_slice(&props_buf);

        let header = WireHeader::new(MAGIC_CREATE_CHANNEL_RESPONSE, DEFAULT_CHANNEL, 0, 0);
        let frame = encode_frame(header, &payload);
        let decoded = decode_frame(&frame, None).expect("decode frame");
        assert_eq!(decoded.consumed, frame.len());

        let parsed = parse_response(decoded.message).expect("parse response");
        assert_eq!(parsed.header.magic, MAGIC_CREATE_CHANNEL_RESPONSE);
        match parsed.response {
            WireResponse::CreateChannel {
                nonce: parsed_nonce,
                channel: parsed_channel,
                properties,
                handshake_hash,
            } => {
                assert_eq!(parsed_nonce, nonce);
                assert_eq!(parsed_channel, channel);
                assert_eq!(properties.internal_model, "T2B1");
                assert_eq!(properties.model_variant, 1);
                assert_eq!(properties.protocol_version_major, 1);
                assert_eq!(properties.protocol_version_minor, 2);
                assert_eq!(properties.pairing_methods.len(), 1);
                let expected_hash = get_handshake_hash(&props_buf);
                assert_eq!(hex_encode(handshake_hash), hex_encode(expected_hash));
            }
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[test]
    fn ack_frame_parses() {
        let header = WireHeader::new(MAGIC_READ_ACK, 0x0042, 1, 0);
        let frame = encode_frame(header, &[]);
        let decoded = decode_frame(&frame, Some(0x0042)).expect("decode");
        let parsed = parse_response(decoded.message).expect("parse");
        assert!(matches!(parsed.response, WireResponse::Ack));
    }

    #[test]
    fn handshake_completion_requires_encrypted_state_and_tag() {
        let header = WireHeader::new(MAGIC_HANDSHAKE_COMPLETION_RESPONSE, 0x0042, 0, 0);
        let frame = encode_frame(header, &[0xAA; 1]);
        let decoded = decode_frame(&frame, Some(0x0042)).expect("decode");
        match parse_response(decoded.message) {
            Err(WireError::ShortPacket) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("short payload should fail"),
        }
    }

    #[test]
    fn state_tracks_encrypted_expected_responses() {
        let mut state = ThpWireState::new();
        assert!(state.expected_responses().is_empty());

        state.on_send(MAGIC_CONTROL_ENCRYPTED);
        assert_eq!(
            state.expected_responses(),
            &[MAGIC_CONTROL_ENCRYPTED, MAGIC_CONTINUATION]
        );
        assert_eq!(state.send_nonce(), 1);

        state.on_receive(MAGIC_CONTROL_ENCRYPTED);
        assert_eq!(state.recv_bit(), 1);
        assert_eq!(state.recv_nonce(), 2);
    }

    #[test]
    fn ack_frames_do_not_advance_sync_or_nonce() {
        let mut state = ThpWireState::new();
        let initial_send_bit = state.send_bit();
        let initial_send_ack_bit = state.send_ack_bit();
        let initial_send_nonce = state.send_nonce();

        state.on_send(MAGIC_READ_ACK);

        assert_eq!(state.send_bit(), initial_send_bit);
        assert_eq!(state.send_ack_bit(), initial_send_ack_bit);
        assert_eq!(state.send_nonce(), initial_send_nonce);
    }

    #[test]
    fn handshake_flow_updates_state() {
        let mut state = ThpWireState::new();

        let nonce = [0x11u8; 8];
        let request = encode_create_channel_request(&nonce);
        assert_eq!(request[0], MAGIC_CREATE_CHANNEL_REQUEST);

        state.on_send(MAGIC_CREATE_CHANNEL_REQUEST);
        assert_eq!(state.expected_responses(), &[MAGIC_CREATE_CHANNEL_RESPONSE]);
        assert_eq!(state.send_bit(), 0);

        let channel = 0x0042u16;
        let props = proto::ThpDeviceProperties {
            internal_model: "T2B1".into(),
            model_variant: Some(1),
            protocol_version_major: 1,
            protocol_version_minor: 0,
            pairing_methods: vec![proto::ThpPairingMethod::QrCode as i32],
        };

        let mut props_buf = Vec::new();
        props.encode(&mut props_buf).unwrap();

        let mut payload = nonce.to_vec();
        payload.extend_from_slice(&channel.to_be_bytes());
        payload.extend_from_slice(&props_buf);

        let response_header = WireHeader::new(MAGIC_CREATE_CHANNEL_RESPONSE, DEFAULT_CHANNEL, 0, 0);
        let frame = encode_frame(response_header, &payload);
        let decoded = decode_frame(&frame, None).expect("decode frame");
        let parsed = parse_response(decoded.message).expect("parse response");
        state.on_receive(parsed.header.magic);
        state.set_expected_responses(Vec::new());
        assert_eq!(state.recv_bit(), 0); // create-channel does not toggle sync bits

        if let WireResponse::CreateChannel {
            properties,
            handshake_hash,
            ..
        } = parsed.response
        {
            assert_eq!(properties.internal_model, "T2B1");
            assert_eq!(handshake_hash, get_handshake_hash(&props_buf));
            state.set_channel(channel);
            state.set_handshake_hash(handshake_hash);
        } else {
            panic!("unexpected response kind");
        }

        let host_ephemeral = [0xAAu8; 32];
        let init_req = encode_handshake_init_request(
            state.channel(),
            state.send_bit(),
            &host_ephemeral,
            false,
        );
        assert_eq!(init_req[0] & !SEQ_BIT, MAGIC_HANDSHAKE_INIT_REQUEST);

        state.on_send(MAGIC_HANDSHAKE_INIT_REQUEST);
        assert_eq!(
            state.expected_responses(),
            &[MAGIC_HANDSHAKE_INIT_RESPONSE, MAGIC_CONTINUATION]
        );

        let mut init_payload = Vec::new();
        init_payload.extend_from_slice(&[0x42u8; 32]);
        init_payload.extend_from_slice(&[0x55; 48]);
        init_payload.extend_from_slice(&[0xAA; 16]);
        let init_header = WireHeader::new(MAGIC_HANDSHAKE_INIT_RESPONSE, state.channel(), 0, 0);
        let frame = encode_frame(init_header, &init_payload);
        let decoded = decode_frame(&frame, Some(state.channel())).expect("decode init frame");
        let parsed = parse_response(decoded.message).expect("parse init response");
        state.on_receive(parsed.header.magic);
        state.set_expected_responses(Vec::new());
        assert_eq!(state.recv_bit(), 1);
        assert_eq!(state.recv_nonce(), 1); // handshake messages do not advance nonce

        let completion_header =
            WireHeader::new(MAGIC_HANDSHAKE_COMPLETION_RESPONSE, state.channel(), 0, 0);
        let mut completion_payload = [0xAAu8; 17];
        completion_payload[0] = 1;
        let completion_frame = encode_frame(completion_header, &completion_payload);
        state.on_send(MAGIC_HANDSHAKE_COMPLETION_REQUEST);
        assert_eq!(
            state.expected_responses(),
            &[MAGIC_HANDSHAKE_COMPLETION_RESPONSE, MAGIC_CONTINUATION]
        );

        let decoded = decode_frame(&completion_frame, Some(state.channel())).unwrap();
        let parsed = parse_response(decoded.message).unwrap();
        state.on_receive(parsed.header.magic);
        state.set_expected_responses(Vec::new());
        assert_eq!(state.recv_bit(), 0);
    }
}
