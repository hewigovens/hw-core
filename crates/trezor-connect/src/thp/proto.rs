use std::convert::TryFrom;

use hex::{FromHex, ToHex};
use hw_chain::Chain;
use prost::Message;
use thiserror::Error;

use super::messages;
use super::types::{
    CodeEntryChallengeResponse, CredentialRequest, CredentialResponse, GetAddressRequest,
    GetAddressResponse, PairingMethod, PairingRequest, PairingRequestApproved, PairingTagResponse,
    SelectMethodRequest, SelectMethodResponse, SignTxRequest, ThpProperties,
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
struct EthereumAddress {
    #[prost(bytes = "vec", optional, tag = "1")]
    old_address: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
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
        Chain::Bitcoin => Err(ProtoMappingError::UnsupportedChain(Chain::Bitcoin)),
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
        Chain::Bitcoin => Err(ProtoMappingError::UnsupportedChain(Chain::Bitcoin)),
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
        Chain::Bitcoin => Err(ProtoMappingError::UnsupportedChain(Chain::Bitcoin)),
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
        Chain::Bitcoin => Err(ProtoMappingError::UnsupportedChain(Chain::Bitcoin)),
    }
}

pub fn encode_sign_tx_request(
    request: &SignTxRequest,
) -> Result<(EncodedMessage, usize), ProtoMappingError> {
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
}
