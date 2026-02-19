use std::convert::TryFrom;

use bs58::encode as base58_encode;
use hex::{FromHex, ToHex};
use hw_chain::Chain;
use prost::Message;
use thiserror::Error;

use super::messages;
use super::types::{
    BtcInputScriptType, BtcOutputScriptType, CodeEntryChallengeResponse, CredentialRequest,
    CredentialResponse, GetAddressRequest, GetAddressResponse, PairingMethod, PairingRequest,
    PairingRequestApproved, PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
    SignTxRequest, ThpProperties,
};

#[derive(Debug, Error)]
pub enum ProtoMappingError {
    #[error("prost encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("prost decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid enum value: {0}")]
    InvalidEnum(i32),
    #[error("invalid hex string")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("unsupported chain: {0:?}")]
    UnsupportedChain(Chain),
    #[error("unexpected message type {0}")]
    UnexpectedMessage(u16),
}

pub struct EncodedMessage {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

const MESSAGE_TYPE_ETHEREUM_GET_ADDRESS: u16 = 56;
const MESSAGE_TYPE_ETHEREUM_ADDRESS: u16 = 57;
const MESSAGE_TYPE_ETHEREUM_GET_PUBLIC_KEY: u16 = 450;
const MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY: u16 = 451;
const MESSAGE_TYPE_BITCOIN_GET_ADDRESS: u16 = 29;
const MESSAGE_TYPE_BITCOIN_ADDRESS: u16 = 30;
const MESSAGE_TYPE_BITCOIN_GET_PUBLIC_KEY: u16 = 11;
const MESSAGE_TYPE_BITCOIN_PUBLIC_KEY: u16 = 12;
pub const MESSAGE_TYPE_BITCOIN_SIGN_TX: u16 = 15;
pub const MESSAGE_TYPE_BITCOIN_TX_REQUEST: u16 = 21;
pub const MESSAGE_TYPE_BITCOIN_TX_ACK: u16 = 22;
const MESSAGE_TYPE_SOLANA_GET_PUBLIC_KEY: u16 = 900;
const MESSAGE_TYPE_SOLANA_PUBLIC_KEY: u16 = 901;
const MESSAGE_TYPE_SOLANA_GET_ADDRESS: u16 = 902;
const MESSAGE_TYPE_SOLANA_ADDRESS: u16 = 903;
pub const MESSAGE_TYPE_SOLANA_SIGN_TX: u16 = 904;
pub const MESSAGE_TYPE_SOLANA_TX_SIGNATURE: u16 = 905;
pub const MESSAGE_TYPE_ETHEREUM_SIGN_TX_EIP1559: u16 = 452;
pub const MESSAGE_TYPE_ETHEREUM_TX_REQUEST: u16 = 59;
pub const MESSAGE_TYPE_ETHEREUM_TX_ACK: u16 = 60;

pub const ETH_DATA_CHUNK_SIZE: usize = 1024;

#[derive(Clone, PartialEq, Message)]
struct EthereumGetAddress {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
    #[prost(bytes = "vec", optional, tag = "3")]
    encoded_network: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "4")]
    chunkify: Option<bool>,
}

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
struct SolanaGetAddress {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaAddress {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumAddress {
    #[prost(bytes = "vec", optional, tag = "1")]
    old_address: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
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
struct EthereumGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaPublicKey {
    #[prost(bytes = "vec", required, tag = "1")]
    public_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaSignTx {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    serialized_tx: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaTxSignature {
    #[prost(bytes = "vec", required, tag = "1")]
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
    /// Binary outputs (TxOutputBinType) used for previous-transaction responses.
    #[prost(message, repeated, tag = "3")]
    bin_outputs: Vec<BitcoinTxBinOutput>,
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
}

#[derive(Clone, PartialEq, Message)]
struct BitcoinTxInput {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    address_n: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    prev_hash: Vec<u8>,
    #[prost(uint32, required, tag = "3")]
    prev_index: u32,
    /// Raw scriptSig bytes; used only when sending a previous-transaction input.
    #[prost(bytes = "vec", optional, tag = "4")]
    script_sig: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    sequence: Option<u32>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "6")]
    script_type: Option<i32>,
    #[prost(uint64, optional, tag = "8")]
    amount: Option<u64>,
}

/// Binary output format used for previous-transaction outputs (`TxOutputBinType` in firmware).
#[derive(Clone, PartialEq, Message)]
struct BitcoinTxBinOutput {
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

#[derive(Clone, PartialEq, Message)]
struct EthereumPublicKey {
    #[prost(string, optional, tag = "2")]
    xpub: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumAccessList {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    storage_keys: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumSignTxEip1559 {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    nonce: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    max_gas_fee: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    max_priority_fee: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    gas_limit: Option<Vec<u8>>,
    #[prost(string, optional, tag = "6")]
    to: Option<String>,
    #[prost(bytes = "vec", optional, tag = "7")]
    value: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "8")]
    data_initial_chunk: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "9")]
    data_length: Option<u32>,
    #[prost(uint64, required, tag = "10")]
    chain_id: u64,
    #[prost(message, repeated, tag = "11")]
    access_list: Vec<EthereumAccessList>,
    #[prost(bool, optional, tag = "13")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumSignTxEip1559PaymentReqProbe {
    #[prost(bytes = "vec", optional, tag = "14")]
    payment_req: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTxRequest {
    #[prost(uint32, optional, tag = "1")]
    pub data_length: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub signature_v: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub signature_r: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub signature_s: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumTxAck {
    #[prost(bytes = "vec", optional, tag = "1")]
    data_chunk: Option<Vec<u8>>,
}

fn encode_message<M: Message>(
    message_type: messages::ThpMessageType,
    message: &M,
) -> Result<EncodedMessage, ProtoMappingError> {
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: message_type as i32 as u16,
        payload,
    })
}

pub fn encode_pairing_request(
    request: &PairingRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpPairingRequest {
        host_name: request.host_name.clone(),
        app_name: request.app_name.clone(),
    };
    encode_message(messages::ThpMessageType::ThpPairingRequest, &message)
}

pub fn decode_pairing_request_approved(
    payload: &[u8],
) -> Result<PairingRequestApproved, ProtoMappingError> {
    let _ = messages::ThpPairingRequestApproved::decode(payload)?;
    Ok(PairingRequestApproved)
}

pub fn encode_select_method(
    request: &SelectMethodRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpSelectMethod {
        selected_pairing_method: pairing_method_to_proto(request.method),
    };
    encode_message(messages::ThpMessageType::ThpSelectMethod, &message)
}

pub fn decode_select_method_response(
    message_type: messages::ThpMessageType,
    payload: &[u8],
) -> Result<SelectMethodResponse, ProtoMappingError> {
    match message_type {
        messages::ThpMessageType::ThpEndResponse => {
            let _ = messages::ThpEndResponse::decode(payload)?;
            Ok(SelectMethodResponse::End)
        }
        messages::ThpMessageType::ThpCodeEntryCommitment => {
            let msg = messages::ThpCodeEntryCommitment::decode(payload)?;
            Ok(SelectMethodResponse::CodeEntryCommitment {
                commitment: msg.commitment,
            })
        }
        messages::ThpMessageType::ThpPairingPreparationsFinished => {
            let _ = messages::ThpPairingPreparationsFinished::decode(payload)?;
            Ok(SelectMethodResponse::PairingPreparationsFinished { nfc_data: None })
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(
            message_type as i32 as u16,
        )),
    }
}

pub fn encode_code_entry_challenge(challenge: &[u8]) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpCodeEntryChallenge {
        challenge: challenge.to_vec(),
    };
    encode_message(messages::ThpMessageType::ThpCodeEntryChallenge, &message)
}

pub fn decode_code_entry_cpace_response(
    payload: &[u8],
) -> Result<CodeEntryChallengeResponse, ProtoMappingError> {
    let msg = messages::ThpCodeEntryCpaceTrezor::decode(payload)?;
    Ok(CodeEntryChallengeResponse {
        trezor_cpace_public_key: msg.cpace_trezor_public_key,
    })
}

pub fn encode_qr_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpQrCodeTag {
        tag: Vec::from_hex(tag)?,
    };
    encode_message(messages::ThpMessageType::ThpQrCodeTag, &message)
}

pub fn encode_nfc_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpNfcTagHost {
        tag: Vec::from_hex(tag)?,
    };
    encode_message(messages::ThpMessageType::ThpNfcTagHost, &message)
}

pub fn encode_code_entry_tag(
    cpace_host_public_key: &[u8],
    tag: &[u8],
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = messages::ThpCodeEntryCpaceHostTag {
        cpace_host_public_key: cpace_host_public_key.to_vec(),
        tag: tag.to_vec(),
    };
    encode_message(messages::ThpMessageType::ThpCodeEntryCpaceHostTag, &message)
}

pub struct ParsedTagResponse {
    pub secret: Vec<u8>,
}

pub fn decode_tag_response(
    message_type: messages::ThpMessageType,
    payload: &[u8],
) -> Result<ParsedTagResponse, ProtoMappingError> {
    match message_type {
        messages::ThpMessageType::ThpQrCodeSecret => {
            let msg = messages::ThpQrCodeSecret::decode(payload)?;
            Ok(ParsedTagResponse { secret: msg.secret })
        }
        messages::ThpMessageType::ThpNfcTagTrezor => {
            let msg = messages::ThpNfcTagTrezor::decode(payload)?;
            Ok(ParsedTagResponse { secret: msg.tag })
        }
        messages::ThpMessageType::ThpCodeEntrySecret => {
            let msg = messages::ThpCodeEntrySecret::decode(payload)?;
            Ok(ParsedTagResponse { secret: msg.secret })
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(
            message_type as i32 as u16,
        )),
    }
}

pub fn to_pairing_tag_response(parsed: ParsedTagResponse) -> PairingTagResponse {
    PairingTagResponse::Accepted {
        secret: parsed.secret,
    }
}

fn pairing_method_to_proto(method: PairingMethod) -> i32 {
    match method {
        PairingMethod::SkipPairing => messages::ThpPairingMethod::SkipPairing as i32,
        PairingMethod::CodeEntry => messages::ThpPairingMethod::CodeEntry as i32,
        PairingMethod::QrCode => messages::ThpPairingMethod::QrCode as i32,
        PairingMethod::Nfc => messages::ThpPairingMethod::Nfc as i32,
    }
}

pub fn proto_to_pairing_methods(values: &[i32]) -> Result<Vec<PairingMethod>, ProtoMappingError> {
    values
        .iter()
        .map(|v| match messages::ThpPairingMethod::try_from(*v) {
            Ok(messages::ThpPairingMethod::SkipPairing) => Ok(PairingMethod::SkipPairing),
            Ok(messages::ThpPairingMethod::CodeEntry) => Ok(PairingMethod::CodeEntry),
            Ok(messages::ThpPairingMethod::QrCode) => Ok(PairingMethod::QrCode),
            Ok(messages::ThpPairingMethod::Nfc) => Ok(PairingMethod::Nfc),
            Err(_) => Err(ProtoMappingError::InvalidEnum(*v)),
        })
        .collect()
}

pub fn encode_credential_request(
    request: &CredentialRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let credential_bytes = request.credential.as_ref().map(Vec::from_hex).transpose()?;

    let message = messages::ThpCredentialRequest {
        host_static_public_key: request.host_static_public_key.clone(),
        autoconnect: Some(request.autoconnect),
        credential: credential_bytes,
    };
    encode_message(messages::ThpMessageType::ThpCredentialRequest, &message)
}

pub fn decode_credential_response(payload: &[u8]) -> Result<CredentialResponse, ProtoMappingError> {
    let msg = messages::ThpCredentialResponse::decode(payload)?;
    let credential_hex = msg.credential.encode_hex::<String>();

    Ok(CredentialResponse {
        trezor_static_public_key: msg.trezor_static_public_key,
        credential: credential_hex,
        autoconnect: false,
    })
}

pub fn encode_end_request() -> Result<EncodedMessage, ProtoMappingError> {
    encode_message(
        messages::ThpMessageType::ThpEndRequest,
        &messages::ThpEndRequest {},
    )
}

pub fn decode_device_properties(payload: &[u8]) -> Result<ThpProperties, ProtoMappingError> {
    let msg = messages::ThpDeviceProperties::decode(payload)?;
    let pairing_methods = proto_to_pairing_methods(&msg.pairing_methods)?;
    Ok(ThpProperties {
        internal_model: msg.internal_model,
        model_variant: msg.model_variant.unwrap_or(0),
        protocol_version_major: msg.protocol_version_major,
        protocol_version_minor: msg.protocol_version_minor,
        pairing_methods,
    })
}

pub fn encode_get_address_request(
    request: &GetAddressRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    match request.chain {
        Chain::Ethereum => {
            let message = EthereumGetAddress {
                path: request.path.clone(),
                show_display: Some(request.show_display),
                encoded_network: request.encoded_network.clone(),
                chunkify: Some(request.chunkify),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_ETHEREUM_GET_ADDRESS,
                payload,
            })
        }
        Chain::Bitcoin => {
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
        Chain::Solana => {
            let message = SolanaGetAddress {
                path: request.path.clone(),
                show_display: Some(request.show_display),
                chunkify: Some(request.chunkify),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_SOLANA_GET_ADDRESS,
                payload,
            })
        }
    }
}

pub fn decode_get_address_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<GetAddressResponse, ProtoMappingError> {
    match chain {
        Chain::Ethereum => {
            if message_type != MESSAGE_TYPE_ETHEREUM_ADDRESS {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }

            let message = EthereumAddress::decode(payload)?;
            let address = message
                .address
                .or_else(|| {
                    message
                        .old_address
                        .map(|bytes| format!("0x{}", hex::encode(bytes)))
                })
                .ok_or(ProtoMappingError::UnexpectedMessage(message_type))?;

            Ok(GetAddressResponse {
                chain,
                address,
                mac: message.mac,
                public_key: None,
            })
        }
        Chain::Bitcoin => {
            if message_type != MESSAGE_TYPE_BITCOIN_ADDRESS {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            let message = BitcoinAddress::decode(payload)?;
            Ok(GetAddressResponse {
                chain,
                address: message.address,
                mac: message.mac,
                public_key: None,
            })
        }
        Chain::Solana => {
            if message_type != MESSAGE_TYPE_SOLANA_ADDRESS {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            let message = SolanaAddress::decode(payload)?;
            Ok(GetAddressResponse {
                chain,
                address: message.address,
                mac: message.mac,
                public_key: None,
            })
        }
    }
}

pub fn encode_get_public_key_request(
    chain: Chain,
    path: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
    match chain {
        Chain::Ethereum => {
            let message = EthereumGetPublicKey {
                path: path.to_vec(),
                show_display: Some(show_display),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_ETHEREUM_GET_PUBLIC_KEY,
                payload,
            })
        }
        Chain::Bitcoin => {
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
        Chain::Solana => {
            let message = SolanaGetPublicKey {
                path: path.to_vec(),
                show_display: Some(show_display),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_SOLANA_GET_PUBLIC_KEY,
                payload,
            })
        }
    }
}

pub fn decode_get_public_key_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<String, ProtoMappingError> {
    match chain {
        Chain::Ethereum => {
            if message_type != MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            let message = EthereumPublicKey::decode(payload)?;
            message
                .xpub
                .ok_or(ProtoMappingError::UnexpectedMessage(message_type))
        }
        Chain::Bitcoin => {
            if message_type != MESSAGE_TYPE_BITCOIN_PUBLIC_KEY {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            let message = BitcoinPublicKey::decode(payload)?;
            Ok(message.xpub)
        }
        Chain::Solana => {
            if message_type != MESSAGE_TYPE_SOLANA_PUBLIC_KEY {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            let message = SolanaPublicKey::decode(payload)?;
            Ok(base58_encode(message.public_key).into_string())
        }
    }
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

pub fn encode_sign_tx_request(
    request: &SignTxRequest,
) -> Result<(EncodedMessage, usize), ProtoMappingError> {
    match request.chain {
        Chain::Ethereum => {
            let initial_chunk_len = request.data.len().min(ETH_DATA_CHUNK_SIZE);
            let data_initial_chunk = if request.data.is_empty() {
                None
            } else {
                Some(request.data[..initial_chunk_len].to_vec())
            };

            let message = EthereumSignTxEip1559 {
                path: request.path.clone(),
                nonce: Some(request.nonce.clone()),
                max_gas_fee: Some(request.max_fee_per_gas.clone()),
                max_priority_fee: Some(request.max_priority_fee.clone()),
                gas_limit: Some(request.gas_limit.clone()),
                to: if request.to.is_empty() {
                    None
                } else {
                    Some(request.to.clone())
                },
                value: Some(request.value.clone()),
                data_initial_chunk,
                data_length: Some(request.data.len() as u32),
                chain_id: request.chain_id,
                access_list: request
                    .access_list
                    .iter()
                    .map(|entry| EthereumAccessList {
                        address: entry.address.clone(),
                        storage_keys: entry.storage_keys.clone(),
                    })
                    .collect(),
                chunkify: Some(request.chunkify),
            };

            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok((
                EncodedMessage {
                    message_type: MESSAGE_TYPE_ETHEREUM_SIGN_TX_EIP1559,
                    payload,
                },
                initial_chunk_len,
            ))
        }
        Chain::Bitcoin => {
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
        Chain::Solana => {
            let message = SolanaSignTx {
                path: request.path.clone(),
                serialized_tx: request.data.clone(),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok((
                EncodedMessage {
                    message_type: MESSAGE_TYPE_SOLANA_SIGN_TX,
                    payload,
                },
                0,
            ))
        }
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
    input: &super::types::BtcSignInput,
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
    output: &super::types::BtcSignOutput,
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
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

/// Encode a `TxAck` for the **metadata** of a referenced (previous) transaction.
///
/// Called when the firmware sends `TXMETA` with `tx_hash` set.
pub fn encode_bitcoin_tx_ack_prev_meta(
    ref_tx: &super::types::RefTx,
) -> Result<EncodedMessage, ProtoMappingError> {
    let extra_data_len = ref_tx
        .extra_data
        .as_ref()
        .map(|d| d.len() as u32)
        .filter(|&n| n > 0);
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: Some(ref_tx.version),
            inputs: Vec::new(),
            bin_outputs: Vec::new(),
            lock_time: Some(ref_tx.lock_time),
            outputs: Vec::new(),
            inputs_cnt: Some(ref_tx.inputs.len() as u32),
            outputs_cnt: Some(ref_tx.bin_outputs.len() as u32),
            extra_data: None,
            extra_data_len,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

/// Encode a `TxAck` for a single input of a referenced (previous) transaction.
///
/// Called when the firmware sends `TXINPUT` with `tx_hash` set.
pub fn encode_bitcoin_tx_ack_prev_input(
    input: &super::types::RefTxInput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let script_sig = if input.script_sig.is_empty() {
        None
    } else {
        Some(input.script_sig.clone())
    };
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: vec![BitcoinTxInput {
                address_n: Vec::new(),
                prev_hash: input.prev_hash.clone(),
                prev_index: input.prev_index,
                script_sig,
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
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

/// Encode a `TxAck` for a single binary output of a referenced (previous) transaction.
///
/// Called when the firmware sends `TXOUTPUT` with `tx_hash` set.
pub fn encode_bitcoin_tx_ack_prev_output(
    output: &super::types::RefTxBinOutput,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = BitcoinTxAck {
        tx: Some(BitcoinTxAckTransaction {
            version: None,
            inputs: Vec::new(),
            bin_outputs: vec![BitcoinTxBinOutput {
                amount: output.amount,
                script_pubkey: output.script_pubkey.clone(),
            }],
            lock_time: None,
            outputs: Vec::new(),
            inputs_cnt: None,
            outputs_cnt: None,
            extra_data: None,
            extra_data_len: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

/// Encode a `TxAck` for a chunk of extra data from a referenced (previous) transaction.
///
/// Called when the firmware sends `TXEXTRADATA` with `tx_hash` set.
pub fn encode_bitcoin_tx_ack_prev_extra_data(
    chunk: &[u8],
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
            extra_data: Some(chunk.to_vec()),
            extra_data_len: None,
        }),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_BITCOIN_TX_ACK,
        payload,
    })
}

pub fn decode_solana_tx_signature(
    message_type: u16,
    payload: &[u8],
) -> Result<Vec<u8>, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_SOLANA_TX_SIGNATURE {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = SolanaTxSignature::decode(payload)?;
    Ok(message.signature)
}

pub fn decode_tx_request(
    message_type: u16,
    payload: &[u8],
) -> Result<EthereumTxRequest, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_ETHEREUM_TX_REQUEST {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    EthereumTxRequest::decode(payload).map_err(ProtoMappingError::from)
}

pub fn encode_tx_ack(data_chunk: &[u8]) -> Result<EncodedMessage, ProtoMappingError> {
    let message = EthereumTxAck {
        data_chunk: Some(data_chunk.to_vec()),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_ETHEREUM_TX_ACK,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_ethereum_get_address_request() {
        let request =
            GetAddressRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0])
                .with_show_display(true)
                .with_chunkify(true);
        let encoded = encode_get_address_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_GET_ADDRESS);

        let decoded = EthereumGetAddress::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.chunkify, Some(true));
    }

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
        let encoded = encode_get_public_key_request(Chain::Bitcoin, &path, true).unwrap();
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
    fn encodes_solana_get_address_request() {
        let request =
            GetAddressRequest::solana(vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000])
                .with_show_display(true)
                .with_chunkify(true);
        let encoded = encode_get_address_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_SOLANA_GET_ADDRESS);

        let decoded = SolanaGetAddress::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn decodes_ethereum_address_response_with_mac() {
        let message = EthereumAddress {
            old_address: None,
            address: Some("0x1234".into()),
            mac: Some(vec![0xAA, 0xBB]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response =
            decode_get_address_response(Chain::Ethereum, MESSAGE_TYPE_ETHEREUM_ADDRESS, &payload)
                .unwrap();
        assert_eq!(response.address, "0x1234");
        assert_eq!(response.mac, Some(vec![0xAA, 0xBB]));
        assert!(response.public_key.is_none());
    }

    #[test]
    fn decodes_ethereum_address_response_from_legacy_field() {
        let message = EthereumAddress {
            old_address: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            address: None,
            mac: None,
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response =
            decode_get_address_response(Chain::Ethereum, MESSAGE_TYPE_ETHEREUM_ADDRESS, &payload)
                .unwrap();
        assert_eq!(response.address, "0xdeadbeef");
    }

    #[test]
    fn decodes_ethereum_public_key_response() {
        let message = EthereumPublicKey {
            xpub: Some("xpub-test".into()),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key = decode_get_public_key_response(
            Chain::Ethereum,
            MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY,
            &payload,
        )
        .unwrap();
        assert_eq!(public_key, "xpub-test");
    }

    #[test]
    fn decodes_bitcoin_address_response() {
        let message = BitcoinAddress {
            address: "bc1qtest".into(),
            mac: Some(vec![0xAA, 0xBB]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response =
            decode_get_address_response(Chain::Bitcoin, MESSAGE_TYPE_BITCOIN_ADDRESS, &payload)
                .unwrap();
        assert_eq!(response.address, "bc1qtest");
        assert_eq!(response.mac, Some(vec![0xAA, 0xBB]));
        assert!(response.public_key.is_none());
    }

    #[test]
    fn decodes_solana_address_response() {
        let message = SolanaAddress {
            address: "So1anaAddress".into(),
            mac: Some(vec![0x11, 0x22]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response =
            decode_get_address_response(Chain::Solana, MESSAGE_TYPE_SOLANA_ADDRESS, &payload)
                .unwrap();
        assert_eq!(response.address, "So1anaAddress");
        assert_eq!(response.mac, Some(vec![0x11, 0x22]));
        assert!(response.public_key.is_none());
    }

    #[test]
    fn decodes_bitcoin_public_key_response() {
        let message = BitcoinPublicKey {
            xpub: "xpub6CUGRU".into(),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key = decode_get_public_key_response(
            Chain::Bitcoin,
            MESSAGE_TYPE_BITCOIN_PUBLIC_KEY,
            &payload,
        )
        .unwrap();
        assert_eq!(public_key, "xpub6CUGRU");
    }

    #[test]
    fn decodes_solana_public_key_response_as_base58() {
        let message = SolanaPublicKey {
            public_key: vec![1, 2, 3, 4, 5],
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key =
            decode_get_public_key_response(Chain::Solana, MESSAGE_TYPE_SOLANA_PUBLIC_KEY, &payload)
                .unwrap();
        assert_eq!(public_key, "7bWpTW");
    }

    #[test]
    fn encodes_code_entry_challenge() {
        let challenge = vec![0x42; 32];
        let encoded = encode_code_entry_challenge(&challenge).unwrap();
        assert_eq!(
            encoded.message_type,
            messages::ThpMessageType::ThpCodeEntryChallenge as i32 as u16
        );

        let decoded = messages::ThpCodeEntryChallenge::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.challenge, challenge);
    }

    #[test]
    fn decodes_code_entry_cpace_response() {
        let message = messages::ThpCodeEntryCpaceTrezor {
            cpace_trezor_public_key: vec![0x77; 32],
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let decoded = decode_code_entry_cpace_response(&payload).unwrap();
        assert_eq!(decoded.trezor_cpace_public_key, vec![0x77; 32]);
    }

    #[test]
    fn encodes_sign_tx_request_no_data() {
        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_nonce(vec![1])
            .with_max_fee_per_gas(vec![0x3b, 0x9a, 0xca, 0x00])
            .with_max_priority_fee(vec![0x59, 0x68, 0x2f, 0x00])
            .with_gas_limit(vec![0x52, 0x08])
            .with_to("0xdead".into())
            .with_value(vec![0]);

        let (encoded, offset) = encode_sign_tx_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_SIGN_TX_EIP1559);
        assert_eq!(offset, 0);

        let decoded = EthereumSignTxEip1559::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.chain_id, 1);
        assert_eq!(decoded.nonce, Some(vec![1]));
        assert_eq!(decoded.data_length, Some(0));
        assert!(decoded.data_initial_chunk.is_none());
        assert_eq!(decoded.chunkify, Some(false));

        // Guard against accidental use of field tag 14 for chunkify, which firmware
        // interprets as payment_req and rejects with decode errors.
        let payment_req_probe =
            EthereumSignTxEip1559PaymentReqProbe::decode(encoded.payload.as_slice()).unwrap();
        assert!(payment_req_probe.payment_req.is_none());
    }

    #[test]
    fn encodes_bitcoin_sign_tx_request() {
        let request = SignTxRequest::bitcoin(super::super::types::BtcSignTx {
            version: 2,
            lock_time: 0,
            inputs: vec![super::super::types::BtcSignInput {
                path: vec![0x8000_002c, 0x8000_0000, 0x8000_0000, 0, 0],
                prev_hash: vec![0x11; 32],
                prev_index: 1,
                amount: 1234,
                sequence: 0xffff_fffd,
                script_type: super::super::types::BtcInputScriptType::SpendWitness,
            }],
            outputs: vec![super::super::types::BtcSignOutput {
                address: Some("bc1qtest".to_string()),
                path: Vec::new(),
                amount: 1000,
                script_type: super::super::types::BtcOutputScriptType::PayToAddress,
                op_return_data: None,
            }],
            chunkify: false,
            ref_txs: Vec::new(),
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
    fn encodes_solana_sign_tx_request() {
        let request = SignTxRequest::solana(
            vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000],
            vec![0xAA, 0xBB, 0xCC],
        );
        let (encoded, offset) = encode_sign_tx_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_SOLANA_SIGN_TX);
        assert_eq!(offset, 0);

        let decoded = SolanaSignTx::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.serialized_tx, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decodes_solana_tx_signature_response() {
        let message = SolanaTxSignature {
            signature: vec![0x11; 64],
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let signature =
            decode_solana_tx_signature(MESSAGE_TYPE_SOLANA_TX_SIGNATURE, &payload).unwrap();
        assert_eq!(signature.len(), 64);
        assert_eq!(signature[0], 0x11);
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
    fn encodes_sign_tx_request_splits_large_data() {
        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_to("0xdead".into())
            .with_data(vec![0xAB; 2048]);

        let (encoded, offset) = encode_sign_tx_request(&request).unwrap();
        assert_eq!(offset, ETH_DATA_CHUNK_SIZE);

        let decoded = EthereumSignTxEip1559::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.data_length, Some(2048));
        assert_eq!(
            decoded.data_initial_chunk.as_ref().unwrap().len(),
            ETH_DATA_CHUNK_SIZE
        );
    }

    #[test]
    fn decode_tx_request_with_signature() {
        let message = EthereumTxRequest {
            data_length: None,
            signature_v: Some(1),
            signature_r: Some(vec![0xAA; 32]),
            signature_s: Some(vec![0xBB; 32]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let decoded = decode_tx_request(MESSAGE_TYPE_ETHEREUM_TX_REQUEST, &payload).unwrap();
        assert_eq!(decoded.signature_v, Some(1));
        assert_eq!(decoded.signature_r.unwrap().len(), 32);
    }

    #[test]
    fn decode_tx_request_requesting_more_data() {
        let message = EthereumTxRequest {
            data_length: Some(1024),
            signature_v: None,
            signature_r: None,
            signature_s: None,
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let decoded = decode_tx_request(MESSAGE_TYPE_ETHEREUM_TX_REQUEST, &payload).unwrap();
        assert_eq!(decoded.data_length, Some(1024));
        assert!(decoded.signature_v.is_none());
    }

    #[test]
    fn encode_tx_ack_round_trip() {
        let chunk = vec![0xCC; 512];
        let encoded = encode_tx_ack(&chunk).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_TX_ACK);

        let decoded = EthereumTxAck::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.data_chunk.unwrap(), chunk);
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_meta() {
        use super::super::types::{RefTx, RefTxBinOutput, RefTxInput};

        let ref_tx = RefTx {
            hash: vec![0xAA; 32],
            version: 1,
            lock_time: 500_000,
            inputs: vec![
                RefTxInput {
                    prev_hash: vec![0x11; 32],
                    prev_index: 0,
                    sequence: 0xffff_ffff,
                    script_sig: vec![0x76, 0xa9], // minimal scriptSig
                },
            ],
            bin_outputs: vec![
                RefTxBinOutput { amount: 50_000, script_pubkey: vec![0x76, 0xa9, 0x14] },
                RefTxBinOutput { amount: 25_000, script_pubkey: vec![0x00, 0x14] },
            ],
            extra_data: None,
        };

        let encoded = encode_bitcoin_tx_ack_prev_meta(&ref_tx).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);

        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.version, Some(1));
        assert_eq!(tx.lock_time, Some(500_000));
        assert_eq!(tx.inputs_cnt, Some(1));
        assert_eq!(tx.outputs_cnt, Some(2));
        assert!(tx.extra_data_len.is_none()); // no extra_data
        assert!(tx.inputs.is_empty());
        assert!(tx.bin_outputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_meta_with_extra_data() {
        use super::super::types::{RefTx, RefTxBinOutput, RefTxInput};

        let ref_tx = RefTx {
            hash: vec![0xBB; 32],
            version: 3,
            lock_time: 0,
            inputs: vec![RefTxInput {
                prev_hash: vec![0x22; 32],
                prev_index: 1,
                sequence: 0xffff_fffe,
                script_sig: Vec::new(),
            }],
            bin_outputs: vec![RefTxBinOutput { amount: 1_000_000, script_pubkey: vec![0x51] }],
            extra_data: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };

        let encoded = encode_bitcoin_tx_ack_prev_meta(&ref_tx).unwrap();
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.extra_data_len, Some(4));
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_input_with_script_sig() {
        use super::super::types::RefTxInput;

        let input = RefTxInput {
            prev_hash: vec![0xCC; 32],
            prev_index: 2,
            sequence: 0xffff_fffd,
            script_sig: vec![0x48, 0x30, 0x45], // DER-encoded sig prefix
        };

        let encoded = encode_bitcoin_tx_ack_prev_input(&input).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);

        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.inputs.len(), 1);
        let inp = &tx.inputs[0];
        assert_eq!(inp.prev_hash, vec![0xCC; 32]);
        assert_eq!(inp.prev_index, 2);
        assert_eq!(inp.sequence, Some(0xffff_fffd));
        assert_eq!(inp.script_sig, Some(vec![0x48, 0x30, 0x45]));
        assert!(inp.address_n.is_empty());
        assert!(inp.amount.is_none());
        assert!(inp.script_type.is_none());
        assert!(tx.bin_outputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_input_empty_script_sig() {
        use super::super::types::RefTxInput;

        let input = RefTxInput {
            prev_hash: vec![0x11; 32],
            prev_index: 0,
            sequence: 0xffff_ffff,
            script_sig: Vec::new(), // SegWit — no scriptSig
        };

        let encoded = encode_bitcoin_tx_ack_prev_input(&input).unwrap();
        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let inp = &decoded.tx.unwrap().inputs[0];
        assert!(inp.script_sig.is_none());
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_output() {
        use super::super::types::RefTxBinOutput;

        let output = RefTxBinOutput {
            amount: 1_234_567,
            script_pubkey: vec![0x76, 0xa9, 0x14, 0xDE, 0xAD],
        };

        let encoded = encode_bitcoin_tx_ack_prev_output(&output).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);

        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.bin_outputs.len(), 1);
        assert_eq!(tx.bin_outputs[0].amount, 1_234_567);
        assert_eq!(tx.bin_outputs[0].script_pubkey, vec![0x76, 0xa9, 0x14, 0xDE, 0xAD]);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn encodes_bitcoin_tx_ack_prev_extra_data() {
        let chunk = vec![0xFE, 0xED, 0xFA, 0xCE];
        let encoded = encode_bitcoin_tx_ack_prev_extra_data(&chunk).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_BITCOIN_TX_ACK);

        let decoded = BitcoinTxAck::decode(encoded.payload.as_slice()).unwrap();
        let tx = decoded.tx.unwrap();
        assert_eq!(tx.extra_data, Some(chunk));
        assert!(tx.inputs.is_empty());
        assert!(tx.bin_outputs.is_empty());
    }
}
