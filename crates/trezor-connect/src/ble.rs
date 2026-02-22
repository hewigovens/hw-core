use std::collections::HashMap;
use std::time::Duration;

use ble_transport::{BleBackend as TransportBackend, BleLink, BleSession, DeviceInfo};
use hex;
use prost::Message;
use rand::SeedableRng;
use rand::rngs::StdRng;
use tokio::time;
use tracing::{debug, trace};

use crate::thp::Chain;
use crate::thp::ThpTransport;
use crate::thp::backend::{BackendError, BackendResult, ThpBackend};
use crate::thp::crypto::curve25519::{
    Curve25519KeyPair, derive_public_from_private, get_curve25519_key_pair,
};
use crate::thp::crypto::pairing::{
    HandshakeInitInput, HandshakeInitResponse, get_cpace_host_keys, get_shared_secret,
    handle_handshake_init, validate_code_entry_tag, validate_qr_code_tag,
};
use crate::thp::crypto::{aes256gcm_decrypt, aes256gcm_encrypt, get_iv_from_nonce};
use crate::thp::eip712::{build_struct_ack, resolve_value_for_member_path};
use crate::thp::messages;
use crate::thp::proto::to_pairing_tag_response;
use crate::thp::proto::{
    BitcoinTxRequestType, DecodedBitcoinTxRequest, DecodedTypedDataResponse, ETH_DATA_CHUNK_SIZE,
    EncodedMessage, MESSAGE_TYPE_BITCOIN_TX_REQUEST, MESSAGE_TYPE_ETHEREUM_TX_REQUEST,
    MESSAGE_TYPE_SOLANA_TX_SIGNATURE, ProtoMappingError, decode_bitcoin_tx_request,
    decode_code_entry_cpace_response, decode_credential_response, decode_get_address_response,
    decode_get_public_key_response, decode_pairing_request_approved, decode_select_method_response,
    decode_sign_message_response, decode_sign_typed_data_message, decode_sign_typed_data_response,
    decode_solana_tx_signature, decode_tag_response, decode_tx_request,
    encode_bitcoin_tx_ack_input, encode_bitcoin_tx_ack_meta, encode_bitcoin_tx_ack_output,
    encode_bitcoin_tx_ack_prev_extra_data, encode_bitcoin_tx_ack_prev_input,
    encode_bitcoin_tx_ack_prev_meta, encode_bitcoin_tx_ack_prev_output,
    encode_code_entry_challenge, encode_code_entry_tag, encode_credential_request,
    encode_end_request, encode_get_address_request, encode_get_public_key_request, encode_nfc_tag,
    encode_pairing_request, encode_qr_tag, encode_select_method, encode_sign_message_request,
    encode_sign_tx_request, encode_sign_typed_data_request, encode_tx_ack,
    encode_typed_data_struct_ack, encode_typed_data_value_ack,
};
use crate::thp::types::*;
use crate::thp::wire::{
    self, MAGIC_CONTROL_ENCRYPTED, MAGIC_CREATE_CHANNEL_REQUEST, MAGIC_CREATE_CHANNEL_RESPONSE,
    MAGIC_HANDSHAKE_COMPLETION_REQUEST, MAGIC_HANDSHAKE_INIT_REQUEST, ParsedMessage, ThpWireState,
    WireError, WireResponse,
};
use sha2::{Digest, Sha256};

const MESSAGE_TYPE_SUCCESS: u16 = 2;
const MESSAGE_TYPE_CREATE_SESSION: u16 = 1000;
const MESSAGE_TYPE_FAILURE: u16 = 3;
const MESSAGE_TYPE_BUTTON_REQUEST: u16 = messages::ThpMessageType::ButtonRequest as i32 as u16;
const MESSAGE_TYPE_BUTTON_ACK: u16 = messages::ThpMessageType::ButtonAck as i32 as u16;
const MIN_THP_FRAME_SIZE: usize = 9; // 1 magic + 2 channel + 2 len + 4 crc
const THP_CONTROL_BITS_MASK: u8 = (1 << 3) | (1 << 4);

#[derive(Clone, PartialEq, Message)]
struct FailureProto {
    #[prost(int32, optional, tag = "1")]
    code: Option<i32>,
    #[prost(string, optional, tag = "2")]
    message: Option<String>,
}

#[derive(Debug)]
struct ChunkAccumulator {
    expected_total: usize,
    continuation_header: [u8; 3],
    frame: Vec<u8>,
}

impl ChunkAccumulator {
    fn start(chunk: &[u8]) -> Option<Self> {
        if chunk.len() < 5 {
            return None;
        }
        let expected_total = 5 + u16::from_be_bytes([chunk[3], chunk[4]]) as usize;
        if expected_total < MIN_THP_FRAME_SIZE {
            return None;
        }
        let mut frame = Vec::with_capacity(expected_total);
        let first_copy = expected_total.min(chunk.len());
        frame.extend_from_slice(&chunk[..first_copy]);
        Some(Self {
            expected_total,
            continuation_header: [wire::MAGIC_CONTINUATION, chunk[1], chunk[2]],
            frame,
        })
    }
}

fn ingest_thp_v2_chunk(pending: &mut Option<ChunkAccumulator>, chunk: &[u8]) -> Option<Vec<u8>> {
    if let Some(mut state) = pending.take() {
        if chunk.len() < state.continuation_header.len()
            || chunk[..state.continuation_header.len()] != state.continuation_header
        {
            if let Some(next) = ChunkAccumulator::start(chunk) {
                if next.frame.len() >= next.expected_total {
                    return Some(next.frame[..next.expected_total].to_vec());
                }
                *pending = Some(next);
            }
            return None;
        }

        let remaining = state.expected_total.saturating_sub(state.frame.len());
        let payload_available = chunk.len().saturating_sub(state.continuation_header.len());
        let payload_to_copy = remaining.min(payload_available);
        let payload_start = state.continuation_header.len();
        state
            .frame
            .extend_from_slice(&chunk[payload_start..payload_start + payload_to_copy]);

        if state.frame.len() >= state.expected_total {
            return Some(state.frame[..state.expected_total].to_vec());
        }
        *pending = Some(state);
        return None;
    }

    if let Some(next) = ChunkAccumulator::start(chunk) {
        if next.frame.len() >= next.expected_total {
            return Some(next.frame[..next.expected_total].to_vec());
        }
        *pending = Some(next);
    }
    None
}

fn decode_failure_reason(payload: &[u8]) -> String {
    match FailureProto::decode(payload) {
        Ok(msg) => match (msg.code, msg.message) {
            (Some(code), Some(message)) if !message.is_empty() => {
                format!("firmware failure code={code}: {message}")
            }
            (Some(code), _) => format!("firmware failure code={code}"),
            (_, Some(message)) if !message.is_empty() => message,
            _ => "firmware reported failure".to_string(),
        },
        Err(_) => "firmware reported failure".to_string(),
    }
}

enum BitcoinTxRequestHandling {
    Ack(EncodedMessage),
    Finished,
    Continue,
}

fn request_index(tx_request: &DecodedBitcoinTxRequest, request_name: &str) -> BackendResult<usize> {
    tx_request
        .request_index
        .map(|value| value as usize)
        .ok_or_else(|| {
            BackendError::Transport(format!("{request_name} request missing request_index"))
        })
}

fn build_ref_txs_index(
    btc: &crate::thp::types::BtcSignTx,
) -> HashMap<&[u8], &crate::thp::types::BtcRefTx> {
    btc.ref_txs
        .iter()
        .map(|tx| (tx.hash.as_slice(), tx))
        .collect()
}

fn find_ref_tx<'a>(
    ref_txs_by_hash: &'a HashMap<&'a [u8], &'a crate::thp::types::BtcRefTx>,
    tx_hash: &[u8],
    request_name: &str,
) -> BackendResult<&'a crate::thp::types::BtcRefTx> {
    ref_txs_by_hash.get(tx_hash).copied().ok_or_else(|| {
        BackendError::Transport(format!(
            "{request_name} request references unknown previous transaction hash {}",
            hex::encode(tx_hash)
        ))
    })
}

fn handle_bitcoin_tx_request(
    btc: &crate::thp::types::BtcSignTx,
    ref_txs_by_hash: &HashMap<&[u8], &crate::thp::types::BtcRefTx>,
    tx_request: &DecodedBitcoinTxRequest,
) -> BackendResult<BitcoinTxRequestHandling> {
    match tx_request.request_type {
        Some(BitcoinTxRequestType::TxInput) => {
            let index = request_index(tx_request, "TxInput")?;
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxInput")?;
                let input = ref_tx.inputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxInput request index {} out of bounds for previous transaction {} (inputs={})",
                        index,
                        hex::encode(ref_tx_hash),
                        ref_tx.inputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_prev_input(input)
            } else {
                let input = btc.inputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxInput request index {} out of bounds (inputs={})",
                        index,
                        btc.inputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_input(input)
            }
            .map_err(BleBackend::transport_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxOutput) => {
            let index = request_index(tx_request, "TxOutput")?;
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxOutput")?;
                let output = ref_tx.bin_outputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOutput request index {} out of bounds for previous transaction {} (outputs={})",
                        index,
                        hex::encode(ref_tx_hash),
                        ref_tx.bin_outputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_prev_output(output)
            } else {
                let output = btc.outputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOutput request index {} out of bounds (outputs={})",
                        index,
                        btc.outputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_output(output)
            }
            .map_err(BleBackend::transport_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxMeta) => {
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxMeta")?;
                encode_bitcoin_tx_ack_prev_meta(ref_tx)
            } else {
                encode_bitcoin_tx_ack_meta(
                    btc.version,
                    btc.lock_time,
                    btc.inputs.len(),
                    btc.outputs.len(),
                )
            }
            .map_err(BleBackend::transport_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxExtraData) => {
            let ref_tx_hash = tx_request.tx_hash.as_ref().ok_or_else(|| {
                BackendError::Transport(
                    "TxExtraData request missing tx_hash for previous transaction".into(),
                )
            })?;
            let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxExtraData")?;
            let extra_data_len = tx_request.extra_data_len.ok_or_else(|| {
                BackendError::Transport("TxExtraData request missing extra_data_len".into())
            })? as usize;
            let extra_data_offset = tx_request.extra_data_offset.ok_or_else(|| {
                BackendError::Transport("TxExtraData request missing extra_data_offset".into())
            })? as usize;
            let extra_data = ref_tx.extra_data.as_deref().ok_or_else(|| {
                BackendError::Transport(format!(
                    "TxExtraData requested for previous transaction {} without extra_data",
                    hex::encode(ref_tx_hash)
                ))
            })?;
            let end = extra_data_offset
                .checked_add(extra_data_len)
                .ok_or_else(|| {
                    BackendError::Transport("TxExtraData request range overflows usize".into())
                })?;
            if end > extra_data.len() {
                return Err(BackendError::Transport(format!(
                    "TxExtraData request range [{}, {}) out of bounds for previous transaction {} (extra_data_len={})",
                    extra_data_offset,
                    end,
                    hex::encode(ref_tx_hash),
                    extra_data.len()
                )));
            }
            let ack = encode_bitcoin_tx_ack_prev_extra_data(&extra_data[extra_data_offset..end])
                .map_err(BleBackend::transport_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxFinished) => Ok(BitcoinTxRequestHandling::Finished),
        Some(BitcoinTxRequestType::TxOrigInput)
        | Some(BitcoinTxRequestType::TxOrigOutput)
        | Some(BitcoinTxRequestType::TxPaymentReq) => Err(BackendError::Transport(
            "Bitcoin request type is not implemented yet for this flow; only TXMETA/TXINPUT/TXOUTPUT/TXEXTRADATA are supported for previous transactions in v1".into(),
        )),
        None => Ok(BitcoinTxRequestHandling::Continue),
    }
}

type ResponseOrReason<T> = std::result::Result<T, String>;

pub struct BleBackend {
    inner: TransportBackend,
    device: DeviceInfo,
    transport: ThpTransport,
    handshake_timeout: Duration,
    state: ThpWireState,
    rx_buffer: Vec<u8>,
    continuation: Vec<u8>,
    pending_chunk: Option<ChunkAccumulator>,
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
            pending_chunk: None,
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

    fn transport_error(err: impl std::fmt::Display) -> BackendError {
        BackendError::Transport(err.to_string())
    }

    async fn send_frame(&mut self, frame: Vec<u8>) -> BackendResult<()> {
        let magic = frame.first().copied().unwrap_or(0);
        let base_magic = magic & !THP_CONTROL_BITS_MASK;
        if base_magic == wire::MAGIC_READ_ACK {
            trace!("BLE THP TX frame: magic=0x{magic:02x} len={}", frame.len());
        } else {
            debug!("BLE THP TX frame: magic=0x{magic:02x} len={}", frame.len());
        }
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
                return Err(Self::transport_error(err));
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
                    wire::parse_response(decoded.message).map_err(Self::transport_error)?;
                Ok(Some(parsed))
            }
            Err(WireError::ShortPacket) => Ok(None),
            Err(WireError::UnexpectedChannel { expected, actual }) => {
                match wire::decode_frame(&self.rx_buffer, None) {
                    Ok(decoded) => {
                        debug!(
                            expected_channel = format_args!("0x{expected:04x}"),
                            received_channel = format_args!("0x{actual:04x}"),
                            consumed = decoded.consumed,
                            "BLE THP ignoring frame on foreign channel"
                        );
                        self.rx_buffer.drain(..decoded.consumed);
                    }
                    Err(_) => {
                        debug!(
                            expected_channel = format_args!("0x{expected:04x}"),
                            received_channel = format_args!("0x{actual:04x}"),
                            "BLE THP channel mismatch without recoverable frame; dropping one byte to resync"
                        );
                        self.rx_buffer.drain(..1);
                    }
                }
                trim_zero_padding(&mut self.rx_buffer);
                Ok(None)
            }
            Err(WireError::CrcMismatch) => {
                debug!("BLE THP CRC mismatch while parsing RX buffer; dropping one byte to resync");
                self.rx_buffer.drain(..1);
                trim_zero_padding(&mut self.rx_buffer);
                Ok(None)
            }
            Err(WireError::UnexpectedMagic(magic)) => {
                debug!(
                    "BLE THP unexpected magic 0x{magic:02x} while parsing RX buffer; dropping one byte to resync"
                );
                self.rx_buffer.drain(..1);
                trim_zero_padding(&mut self.rx_buffer);
                Ok(None)
            }
            Err(err) => Err(Self::transport_error(err)),
        }
    }

    fn ingest_chunk(&mut self, chunk: &[u8]) {
        if let Some(frame) = ingest_thp_v2_chunk(&mut self.pending_chunk, chunk) {
            self.rx_buffer.extend_from_slice(&frame);
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
                .map_err(Self::transport_error)?;
            debug!(
                "BLE THP RX chunk: first=0x{:02x} len={}",
                chunk.first().copied().unwrap_or(0),
                chunk.len()
            );
            self.ingest_chunk(&chunk);
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
            let (message_type, payload) = match parsed.response {
                WireResponse::Protobuf { payload } => {
                    if self.should_ack(&parsed.header) {
                        self.send_ack(&parsed.header).await?;
                    }
                    let res = self.decrypt_device_message(&payload)?;
                    self.state.on_receive(parsed.header.magic);
                    res
                }
                WireResponse::Error(code) => {
                    return Err(BackendError::Device(format!(
                        "device returned error code {code}"
                    )));
                }
                other => {
                    debug!(
                        "BLE THP ignoring out-of-phase frame while awaiting encrypted response: {:?}",
                        other
                    );
                    parsed = self.read_next().await?;
                    continue;
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

            let result = decoder(message_type, &payload).map_err(Self::transport_error)?;
            self.state.set_expected_responses(&[]);
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
    match messages::ThpMessageType::try_from(message_type as i32) {
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

mod backend_impl;

#[cfg(test)]
mod tests;
