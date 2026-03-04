use std::convert::TryFrom;

use hw_chain::Chain;
use prost::Message;

use super::{EncodedMessage, ProtoMappingError};
use crate::thp::types::{
    BtcInputScriptType, BtcOutputScriptType, BtcPaymentRequest, BtcPaymentRequestMemo, BtcRefTx,
    BtcRefTxInput, BtcRefTxOutput, BtcSignInput, BtcSignOutput, GetAddressRequest,
    GetAddressResponse, SignMessageRequest, SignMessageResponse, SignTxRequest,
};

const MESSAGE_TYPE_BITCOIN_GET_ADDRESS: u16 = 29;
const MESSAGE_TYPE_BITCOIN_ADDRESS: u16 = 30;
const MESSAGE_TYPE_BITCOIN_GET_PUBLIC_KEY: u16 = 11;
const MESSAGE_TYPE_BITCOIN_PUBLIC_KEY: u16 = 12;
pub const MESSAGE_TYPE_BITCOIN_SIGN_MESSAGE: u16 = 38;
pub const MESSAGE_TYPE_BITCOIN_MESSAGE_SIGNATURE: u16 = 40;
pub const MESSAGE_TYPE_BITCOIN_SIGN_TX: u16 = 15;
pub const MESSAGE_TYPE_BITCOIN_TX_REQUEST: u16 = 21;
pub const MESSAGE_TYPE_BITCOIN_TX_ACK: u16 = 22;
/// `TxAckPaymentRequest` — sent in response to a `TXPAYMENTREQ` firmware request.
pub const MESSAGE_TYPE_BITCOIN_TX_ACK_PAYMENT_REQUEST: u16 = 37;

#[derive(Clone, PartialEq, Message)]
struct BitcoinGetAddress {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(string, optional, tag = "2")]
    coin_name: Option<String>,
    #[prost(bool, optional, tag = "3")]
    show_display: Option<bool>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "5")]
    script_type: Option<i32>,
    #[prost(bool, optional, tag = "7")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinAddress {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "3")]
    show_display: Option<bool>,
    #[prost(string, optional, tag = "4")]
    coin_name: Option<String>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "5")]
    script_type: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinPublicKey {
    #[prost(string, required, tag = "2")]
    xpub: String,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    message: Vec<u8>,
    #[prost(string, optional, tag = "3")]
    coin_name: Option<String>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "4")]
    script_type: Option<i32>,
    #[prost(bool, optional, tag = "6")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct MessageSignature {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", required, tag = "2")]
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinSignTx {
    #[prost(uint32, required, tag = "1")]
    outputs_count: u32,
    #[prost(uint32, required, tag = "2")]
    inputs_count: u32,
    #[prost(string, optional, tag = "3")]
    coin_name: Option<String>,
    #[prost(uint32, optional, tag = "4")]
    version: Option<u32>,
    #[prost(uint32, optional, tag = "5")]
    lock_time: Option<u32>,
    #[prost(bool, optional, tag = "13")]
    serialize: Option<bool>,
    #[prost(bool, optional, tag = "15")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxRequest {
    #[prost(enumeration = "BitcoinTxRequestTypeProto", optional, tag = "1")]
    request_type: Option<i32>,
    #[prost(message, optional, tag = "2")]
    details: Option<BitcoinTxRequestDetails>,
    #[prost(message, optional, tag = "3")]
    serialized: Option<BitcoinTxRequestSerialized>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum BitcoinTxRequestTypeProto {
    Input = 0,
    Output = 1,
    Meta = 2,
    Finished = 3,
    ExtraData = 4,
    OrigInput = 5,
    OrigOutput = 6,
    PaymentReq = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinTxRequestType {
    TxInput,
    TxOutput,
    TxMeta,
    TxFinished,
    TxExtraData,
    TxOrigInput,
    TxOrigOutput,
    TxPaymentReq,
}

impl TryFrom<i32> for BitcoinTxRequestType {
    type Error = ProtoMappingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match BitcoinTxRequestTypeProto::try_from(value) {
            Ok(BitcoinTxRequestTypeProto::Input) => Ok(Self::TxInput),
            Ok(BitcoinTxRequestTypeProto::Output) => Ok(Self::TxOutput),
            Ok(BitcoinTxRequestTypeProto::Meta) => Ok(Self::TxMeta),
            Ok(BitcoinTxRequestTypeProto::Finished) => Ok(Self::TxFinished),
            Ok(BitcoinTxRequestTypeProto::ExtraData) => Ok(Self::TxExtraData),
            Ok(BitcoinTxRequestTypeProto::OrigInput) => Ok(Self::TxOrigInput),
            Ok(BitcoinTxRequestTypeProto::OrigOutput) => Ok(Self::TxOrigOutput),
            Ok(BitcoinTxRequestTypeProto::PaymentReq) => Ok(Self::TxPaymentReq),
            Err(_) => Err(ProtoMappingError::InvalidEnum(value)),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxRequestDetails {
    #[prost(uint32, optional, tag = "1")]
    request_index: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    tx_hash: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "3")]
    extra_data_len: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    extra_data_offset: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxRequestSerialized {
    #[prost(uint32, optional, tag = "1")]
    signature_index: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    serialized_tx: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBitcoinTxRequest {
    pub request_type: Option<BitcoinTxRequestType>,
    pub request_index: Option<u32>,
    pub tx_hash: Option<Vec<u8>>,
    pub extra_data_len: Option<u32>,
    pub extra_data_offset: Option<u32>,
    pub signature_index: Option<u32>,
    pub signature: Option<Vec<u8>>,
    pub serialized_tx: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxAck {
    #[prost(message, optional, tag = "1")]
    tx: Option<BitcoinTxAckTransaction>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxAckTransaction {
    #[prost(uint32, optional, tag = "1")]
    version: Option<u32>,
    #[prost(message, repeated, tag = "2")]
    inputs: Vec<BitcoinTxInput>,
    #[prost(message, repeated, tag = "3")]
    bin_outputs: Vec<BitcoinTxOutputBin>,
    #[prost(uint32, optional, tag = "4")]
    lock_time: Option<u32>,
    #[prost(message, repeated, tag = "5")]
    outputs: Vec<BitcoinTxOutput>,
    #[prost(uint32, optional, tag = "6")]
    inputs_cnt: Option<u32>,
    #[prost(uint32, optional, tag = "7")]
    outputs_cnt: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "8")]
    extra_data: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    extra_data_len: Option<u32>,
    #[prost(uint32, optional, tag = "10")]
    expiry: Option<u32>,
    #[prost(bool, optional, tag = "11")]
    overwintered: Option<bool>,
    #[prost(uint32, optional, tag = "12")]
    version_group_id: Option<u32>,
    #[prost(uint32, optional, tag = "13")]
    timestamp: Option<u32>,
    #[prost(uint32, optional, tag = "14")]
    branch_id: Option<u32>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxInput {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    address_n: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    prev_hash: Vec<u8>,
    #[prost(uint32, required, tag = "3")]
    prev_index: u32,
    #[prost(bytes = "vec", optional, tag = "4")]
    script_sig: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    sequence: Option<u32>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "6")]
    script_type: Option<i32>,
    #[prost(uint64, optional, tag = "8")]
    amount: Option<u64>,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxOutputBin {
    #[prost(uint64, required, tag = "1")]
    amount: u64,
    #[prost(bytes = "vec", required, tag = "2")]
    script_pubkey: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum BitcoinInputScriptTypeProto {
    SpendAddress = 0,
    SpendMultisig = 1,
    External = 2,
    SpendWitness = 3,
    SpendP2ShWitness = 4,
    SpendTaproot = 5,
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxOutput {
    #[prost(string, optional, tag = "1")]
    address: Option<String>,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    address_n: Vec<u32>,
    #[prost(uint64, required, tag = "3")]
    amount: u64,
    #[prost(enumeration = "BitcoinOutputScriptTypeProto", optional, tag = "4")]
    script_type: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "6")]
    op_return_data: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
enum BitcoinOutputScriptTypeProto {
    PayToAddress = 0,
    PayToScriptHash = 1,
    PayToMultisig = 2,
    PayToOpReturn = 3,
    PayToWitness = 4,
    PayToP2ShWitness = 5,
    PayToTaproot = 6,
}

// ── TxAckPaymentRequest proto structs ────────────────────────────────────────

#[derive(Clone, PartialEq, Message)]
struct ProtoTextMemo {
    #[prost(string, optional, tag = "1")]
    text: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoRefundMemo {
    #[prost(string, optional, tag = "1")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoCoinPurchaseMemo {
    #[prost(uint32, optional, tag = "1")]
    coin_type: Option<u32>,
    #[prost(string, optional, tag = "2")]
    amount: Option<String>,
    #[prost(string, optional, tag = "3")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "4")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoPaymentRequestMemo {
    #[prost(message, optional, tag = "1")]
    text_memo: Option<ProtoTextMemo>,
    #[prost(message, optional, tag = "2")]
    refund_memo: Option<ProtoRefundMemo>,
    #[prost(message, optional, tag = "3")]
    coin_purchase_memo: Option<ProtoCoinPurchaseMemo>,
}

#[derive(Clone, PartialEq, Message)]
struct ProtoTxAckPaymentRequest {
    #[prost(bytes = "vec", optional, tag = "1")]
    nonce: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    recipient_name: Option<String>,
    #[prost(message, repeated, tag = "3")]
    memos: Vec<ProtoPaymentRequestMemo>,
    #[prost(uint64, optional, tag = "4")]
    amount: Option<u64>,
    #[prost(bytes = "vec", optional, tag = "5")]
    signature: Option<Vec<u8>>,
}

// ─────────────────────────────────────────────────────────────────────────────

pub(super) fn encode_get_address_request(
    request: &GetAddressRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinGetAddress {
        path: request.path.clone(),
        coin_name: Some("Bitcoin".to_string()),
        show_display: Some(request.show_display),
        script_type: bitcoin_input_script_type_from_path(&request.path),
        chunkify: Some(request.chunkify),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_GET_ADDRESS,
        payload,
    })
}

pub(super) fn decode_get_address_response(
    message_type: u16,
    payload: &[u8],
) -> Result<GetAddressResponse, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_BITCOIN_ADDRESS {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = BitcoinAddress::decode(payload)?;
    Ok(GetAddressResponse {
        chain: Chain::Bitcoin,
        address: message.address,
        mac: message.mac,
        public_key: None,
    })
}

pub(super) fn encode_get_public_key_request(
    path: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinGetPublicKey {
        path: path.to_vec(),
        show_display: Some(show_display),
        coin_name: Some("Bitcoin".to_string()),
        script_type: bitcoin_input_script_type_from_path(path),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_GET_PUBLIC_KEY,
        payload,
    })
}

pub(super) fn decode_get_public_key_response(
    message_type: u16,
    payload: &[u8],
) -> Result<String, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_BITCOIN_PUBLIC_KEY {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = BitcoinPublicKey::decode(payload)?;
    Ok(message.xpub)
}

pub(super) fn encode_sign_message_request(
    request: &SignMessageRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinSignMessage {
        path: request.path.clone(),
        message: request.message.clone(),
        coin_name: Some("Bitcoin".to_string()),
        script_type: Some(bitcoin_sign_message_script_type_from_path(&request.path)),
        chunkify: Some(request.chunkify),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_SIGN_MESSAGE,
        payload,
    })
}

pub(super) fn decode_sign_message_response(
    message_type: u16,
    payload: &[u8],
) -> Result<SignMessageResponse, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_BITCOIN_MESSAGE_SIGNATURE {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = MessageSignature::decode(payload)?;
    Ok(SignMessageResponse {
        chain: Chain::Bitcoin,
        address: message.address,
        signature: message.signature,
    })
}

pub(super) fn encode_sign_tx_request(
    request: &SignTxRequest,
) -> Result<(EncodedMessage, usize), ProtoMappingError> {
    let btc = request
        .btc
        .as_ref()
        .ok_or(ProtoMappingError::UnsupportedChain(Chain::Bitcoin))?;
    let message = BitcoinSignTx {
        outputs_count: btc.outputs.len() as u32,
        inputs_count: btc.inputs.len() as u32,
        coin_name: Some("Bitcoin".to_string()),
        version: Some(btc.version),
        lock_time: Some(btc.lock_time),
        serialize: Some(true),
        chunkify: Some(btc.chunkify),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok((
        EncodedMessage {
            message_type: MESSAGE_TYPE_BITCOIN_SIGN_TX,
            payload,
        },
        0,
    ))
}

fn bitcoin_input_script_type_to_proto(script_type: BtcInputScriptType) -> i32 {
    match script_type {
        BtcInputScriptType::SpendAddress => BitcoinInputScriptTypeProto::SpendAddress as i32,
        BtcInputScriptType::SpendMultisig => BitcoinInputScriptTypeProto::SpendMultisig as i32,
        BtcInputScriptType::External => BitcoinInputScriptTypeProto::External as i32,
        BtcInputScriptType::SpendWitness => BitcoinInputScriptTypeProto::SpendWitness as i32,
        BtcInputScriptType::SpendP2shWitness => {
            BitcoinInputScriptTypeProto::SpendP2ShWitness as i32
        }
        BtcInputScriptType::SpendTaproot => BitcoinInputScriptTypeProto::SpendTaproot as i32,
    }
}

fn unharden(path_index: u32) -> u32 {
    path_index & !0x8000_0000
}

fn bitcoin_sign_message_script_type_from_path(path: &[u32]) -> i32 {
    bitcoin_input_script_type_from_path(path)
        .unwrap_or(BitcoinInputScriptTypeProto::SpendAddress as i32)
}

fn bitcoin_input_script_type_from_path(path: &[u32]) -> Option<i32> {
    let purpose = path.first().copied().map(unharden)?;
    let script_type = match purpose {
        44 => BitcoinInputScriptTypeProto::SpendAddress,
        48 => {
            let script_index = path.get(3).copied().map(unharden)?;
            match script_index {
                0 => BitcoinInputScriptTypeProto::SpendMultisig,
                1 => BitcoinInputScriptTypeProto::SpendP2ShWitness,
                2 => BitcoinInputScriptTypeProto::SpendWitness,
                _ => return None,
            }
        }
        49 => BitcoinInputScriptTypeProto::SpendP2ShWitness,
        84 => BitcoinInputScriptTypeProto::SpendWitness,
        86 | 10025 => BitcoinInputScriptTypeProto::SpendTaproot,
        _ => return None,
    };
    Some(script_type as i32)
}

fn bitcoin_output_script_type_to_proto(script_type: BtcOutputScriptType) -> i32 {
    match script_type {
        BtcOutputScriptType::PayToAddress => BitcoinOutputScriptTypeProto::PayToAddress as i32,
        BtcOutputScriptType::PayToScriptHash => {
            BitcoinOutputScriptTypeProto::PayToScriptHash as i32
        }
        BtcOutputScriptType::PayToMultisig => BitcoinOutputScriptTypeProto::PayToMultisig as i32,
        BtcOutputScriptType::PayToOpReturn => BitcoinOutputScriptTypeProto::PayToOpReturn as i32,
        BtcOutputScriptType::PayToWitness => BitcoinOutputScriptTypeProto::PayToWitness as i32,
        BtcOutputScriptType::PayToP2shWitness => {
            BitcoinOutputScriptTypeProto::PayToP2ShWitness as i32
        }
        BtcOutputScriptType::PayToTaproot => BitcoinOutputScriptTypeProto::PayToTaproot as i32,
    }
}

pub fn decode_bitcoin_tx_request(
    message_type: u16,
    payload: &[u8],
) -> Result<DecodedBitcoinTxRequest, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_BITCOIN_TX_REQUEST {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let request = BitcoinTxRequest::decode(payload)?;
    let request_type = request
        .request_type
        .map(BitcoinTxRequestType::try_from)
        .transpose()?;
    Ok(DecodedBitcoinTxRequest {
        request_type,
        request_index: request
            .details
            .as_ref()
            .and_then(|details| details.request_index),
        tx_hash: request
            .details
            .as_ref()
            .and_then(|details| details.tx_hash.clone()),
        extra_data_len: request
            .details
            .as_ref()
            .and_then(|details| details.extra_data_len),
        extra_data_offset: request
            .details
            .as_ref()
            .and_then(|details| details.extra_data_offset),
        signature_index: request
            .serialized
            .as_ref()
            .and_then(|serialized| serialized.signature_index),
        signature: request
            .serialized
            .as_ref()
            .and_then(|serialized| serialized.signature.clone()),
        serialized_tx: request
            .serialized
            .as_ref()
            .and_then(|serialized| serialized.serialized_tx.clone()),
    })
}

pub fn encode_bitcoin_tx_ack_meta(
    version: u32,
    lock_time: u32,
    inputs_count: usize,
    outputs_count: usize,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: Some(version),
            inputs: Vec::new(),
            bin_outputs: Vec::new(),
            lock_time: Some(lock_time),
            outputs: Vec::new(),
            inputs_cnt: Some(inputs_count as u32),
            outputs_cnt: Some(outputs_count as u32),
            extra_data: None,
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_input(
    input: &BtcSignInput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: vec![BitcoinTxInput {
                address_n: input.path.clone(),
                prev_hash: input.prev_hash.clone(),
                prev_index: input.prev_index,
                script_sig: None,
                sequence: Some(input.sequence),
                script_type: Some(bitcoin_input_script_type_to_proto(input.script_type)),
                amount: Some(input.amount),
            }],
            bin_outputs: Vec::new(),
            lock_time: None,
            outputs: Vec::new(),
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: None,
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_output(
    output: &BtcSignOutput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: Vec::new(),
            bin_outputs: Vec::new(),
            lock_time: None,
            outputs: vec![BitcoinTxOutput {
                address: output.address.clone(),
                address_n: output.path.clone(),
                amount: output.amount,
                script_type: Some(bitcoin_output_script_type_to_proto(output.script_type)),
                op_return_data: output.op_return_data.clone(),
            }],
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: None,
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_prev_meta(tx: &BtcRefTx) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: Some(tx.version),
            inputs: Vec::new(),
            bin_outputs: Vec::new(),
            lock_time: Some(tx.lock_time),
            outputs: Vec::new(),
            inputs_cnt: Some(tx.inputs.len() as u32),
            outputs_cnt: Some(tx.bin_outputs.len() as u32),
            extra_data: None,
            extra_data_len: tx.extra_data.as_ref().map(|data| data.len() as u32),
            expiry: tx.expiry,
            overwintered: None,
            version_group_id: tx.version_group_id,
            timestamp: tx.timestamp,
            branch_id: tx.branch_id,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_prev_input(
    input: &BtcRefTxInput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: vec![BitcoinTxInput {
                address_n: Vec::new(),
                prev_hash: input.prev_hash.clone(),
                prev_index: input.prev_index,
                script_sig: Some(input.script_sig.clone()),
                sequence: Some(input.sequence),
                script_type: None,
                amount: None,
            }],
            bin_outputs: Vec::new(),
            lock_time: None,
            outputs: Vec::new(),
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: None,
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_prev_output(
    output: &BtcRefTxOutput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: Vec::new(),
            bin_outputs: vec![BitcoinTxOutputBin {
                amount: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            }],
            lock_time: None,
            outputs: Vec::new(),
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: None,
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn encode_bitcoin_tx_ack_prev_extra_data(
    extra_data_chunk: &[u8],
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: Vec::new(),
            bin_outputs: Vec::new(),
            lock_time: None,
            outputs: Vec::new(),
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: Some(extra_data_chunk.to_vec()),
            extra_data_len: None,
            expiry: None,
            overwintered: None,
            version_group_id: None,
            timestamp: None,
            branch_id: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

/// Encodes a `TxAckPaymentRequest` response to a firmware `TXPAYMENTREQ` request.
///
/// The firmware sends `TxRequest { type: TXPAYMENTREQ, details.request_index: N }` and
/// expects the host to reply with the payment-request data at index N from the caller-
/// supplied list.  Most signing flows have no payment requests; this encoder is only
/// invoked when the firmware explicitly asks for one.
pub fn encode_bitcoin_tx_ack_payment_request(
    pr: &BtcPaymentRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let memos: Vec<ProtoPaymentRequestMemo> = pr
        .memos
        .iter()
        .map(|m| match m {
            BtcPaymentRequestMemo::Text { text } => ProtoPaymentRequestMemo {
                text_memo: Some(ProtoTextMemo {
                    text: Some(text.clone()),
                }),
                refund_memo: None,
                coin_purchase_memo: None,
            },
            BtcPaymentRequestMemo::Refund { address, mac } => ProtoPaymentRequestMemo {
                text_memo: None,
                refund_memo: Some(ProtoRefundMemo {
                    address: Some(address.clone()),
                    mac: Some(mac.clone()),
                }),
                coin_purchase_memo: None,
            },
            BtcPaymentRequestMemo::CoinPurchase {
                coin_type,
                amount,
                address,
                mac,
            } => ProtoPaymentRequestMemo {
                text_memo: None,
                refund_memo: None,
                coin_purchase_memo: Some(ProtoCoinPurchaseMemo {
                    coin_type: Some(*coin_type),
                    amount: Some(amount.clone()),
                    address: Some(address.clone()),
                    mac: Some(mac.clone()),
                }),
            },
        })
        .collect();

    let message = ProtoTxAckPaymentRequest {
        nonce: pr.nonce.clone(),
        recipient_name: pr.recipient_name.clone(),
        memos,
        amount: pr.amount,
        signature: pr.signature.clone(),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK_PAYMENT_REQUEST,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::{BtcSignTx, GetAddressRequest, SignMessageRequest};

    #[test]
    fn encodes_bitcoin_get_address_request() {
        let request = GetAddressRequest::bitcoin(vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0])
            .with_show_display(true)
            .with_chunkify(true);
        let encoded = encode_get_address_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_GET_ADDRESS);

        let decoded = BitcoinGetAddress::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.coin_name.as_deref(), Some("Bitcoin"));
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(
            decoded.script_type,
            Some(BitcoinInputScriptTypeProto::SpendWitness as i32)
        );
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn encodes_bitcoin_get_public_key_request_sets_script_type() {
        let path = vec![0x8000_0054, 0x8000_0000, 0x8000_0000];
        let encoded = encode_get_public_key_request(&path, true).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_GET_PUBLIC_KEY);

        let decoded = BitcoinGetPublicKey::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, path);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.coin_name.as_deref(), Some("Bitcoin"));
        assert_eq!(
            decoded.script_type,
            Some(BitcoinInputScriptTypeProto::SpendWitness as i32)
        );
    }

    #[test]
    fn decodes_bitcoin_address_response() {
        let message = BitcoinAddress {
            address: "bc1qtest".into(),
            mac: Some(vec![0xAA, 0xBB]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response = decode_get_address_response(MESSAGE_TYPE_BITCOIN_ADDRESS, &payload).unwrap();
        assert_eq!(response.address, "bc1qtest");
        assert_eq!(response.mac, Some(vec![0xAA, 0xBB]));
        assert!(response.public_key.is_none());
    }

    #[test]
    fn decodes_bitcoin_public_key_response() {
        let message = BitcoinPublicKey {
            xpub: "xpub6CUGRU".into(),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key =
            decode_get_public_key_response(MESSAGE_TYPE_BITCOIN_PUBLIC_KEY, &payload).unwrap();
        assert_eq!(public_key, "xpub6CUGRU");
    }

    #[test]
    fn encodes_bitcoin_sign_message_request() {
        let request = SignMessageRequest::bitcoin(
            vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
            b"hello".to_vec(),
        )
        .with_chunkify(true);
        let encoded = encode_sign_message_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_SIGN_MESSAGE);

        let decoded = BitcoinSignMessage::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.message, b"hello");
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn decodes_bitcoin_sign_message_response() {
        let message = MessageSignature {
            address: "bc1qtest".into(),
            signature: vec![0x99; 65],
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response =
            decode_sign_message_response(MESSAGE_TYPE_BITCOIN_MESSAGE_SIGNATURE, &payload).unwrap();
        assert_eq!(response.chain, Chain::Bitcoin);
        assert_eq!(response.address, "bc1qtest");
        assert_eq!(response.signature.len(), 65);
    }

    #[test]
    fn encodes_bitcoin_sign_tx_request() {
        let request = SignTxRequest::bitcoin(BtcSignTx {
            version: 2,
            lock_time: 0,
            inputs: vec![BtcSignInput {
                path: vec![0x8000_002c, 0x8000_0000, 0x8000_0000, 0, 0],
                prev_hash: vec![0x11; 32],
                prev_index: 1,
                amount: 1234,
                sequence: 0xffff_fffd,
                script_type: BtcInputScriptType::SpendWitness,
            }],
            outputs: vec![BtcSignOutput {
                address: Some("bc1qtest".to_string()),
                path: Vec::new(),
                amount: 1000,
                script_type: BtcOutputScriptType::PayToAddress,
                op_return_data: None,
            }],
            ref_txs: Vec::new(),
            payment_reqs: Vec::new(),
            chunkify: false,
        });
        let (encoded, offset) = encode_sign_tx_request(&request).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_SIGN_TX);

        let decoded = BitcoinSignTx::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.inputs_count, 1);
        assert_eq!(decoded.outputs_count, 1);
        assert_eq!(decoded.version, Some(2));
    }

    #[test]
    fn decodes_bitcoin_tx_request() {
        let request = BitcoinTxRequest {
            request_type: Some(BitcoinTxRequestTypeProto::Input as i32),
            details: Some(BitcoinTxRequestDetails {
                request_index: Some(0),
                tx_hash: None,
                extra_data_len: None,
                extra_data_offset: None,
            }),
            serialized: Some(BitcoinTxRequestSerialized {
                signature_index: Some(0),
                signature: Some(vec![0xAA; 64]),
                serialized_tx: Some(vec![0xBB, 0xCC]),
            }),
        };
        let mut payload = Vec::new();
        request.encode(&mut payload).unwrap();

        let decoded = decode_bitcoin_tx_request(MESSAGE_TYPE_BITCOIN_TX_REQUEST, &payload).unwrap();
        assert_eq!(decoded.request_type, Some(BitcoinTxRequestType::TxInput));
        assert_eq!(decoded.request_index, Some(0));
        assert_eq!(decoded.signature_index, Some(0));
        assert_eq!(decoded.signature.unwrap().len(), 64);
    }

    #[test]
    fn encodes_bitcoin_prev_meta_ack() {
        let tx = BtcRefTx {
            hash: vec![0x11; 32],
            version: 2,
            lock_time: 123,
            inputs: vec![BtcRefTxInput {
                prev_hash: vec![0x22; 32],
                prev_index: 0,
                script_sig: vec![0xaa, 0xbb],
                sequence: 0xffff_fffe,
            }],
            bin_outputs: vec![BtcRefTxOutput {
                amount: 1000,
                script_pubkey: vec![0x51],
            }],
            extra_data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            timestamp: Some(42),
            version_group_id: Some(7),
            expiry: Some(9),
            branch_id: Some(11),
        };

        let encoded = encode_bitcoin_tx_ack_prev_meta(&tx).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let meta = decoded.tx.unwrap();
        assert_eq!(meta.version, Some(2));
        assert_eq!(meta.lock_time, Some(123));
        assert_eq!(meta.inputs_cnt, Some(1));
        assert_eq!(meta.outputs_cnt, Some(1));
        assert_eq!(meta.extra_data_len, Some(4));
        assert_eq!(meta.timestamp, Some(42));
        assert_eq!(meta.version_group_id, Some(7));
        assert_eq!(meta.expiry, Some(9));
        assert_eq!(meta.branch_id, Some(11));
    }

    #[test]
    fn encodes_bitcoin_prev_input_ack() {
        let input = BtcRefTxInput {
            prev_hash: vec![0x33; 32],
            prev_index: 1,
            script_sig: vec![0x01, 0x02, 0x03],
            sequence: 0xffff_fffd,
        };
        let encoded = encode_bitcoin_tx_ack_prev_input(&input).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].prev_hash, input.prev_hash);
        assert_eq!(tx.inputs[0].prev_index, 1);
        assert_eq!(tx.inputs[0].script_sig, Some(vec![0x01, 0x02, 0x03]));
        assert_eq!(tx.inputs[0].sequence, Some(0xffff_fffd));
    }

    #[test]
    fn encodes_bitcoin_prev_output_ack() {
        let output = BtcRefTxOutput {
            amount: 123,
            script_pubkey: vec![0x51, 0x21],
        };
        let encoded = encode_bitcoin_tx_ack_prev_output(&output).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.bin_outputs.len(), 1);
        assert_eq!(tx.bin_outputs[0].amount, 123);
        assert_eq!(tx.bin_outputs[0].script_pubkey, vec![0x51, 0x21]);
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn encodes_bitcoin_prev_extra_data_ack() {
        let chunk = vec![0xaa, 0xbb, 0xcc];
        let encoded = encode_bitcoin_tx_ack_prev_extra_data(&chunk).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.extra_data, Some(chunk));
    }
}
