use hex;
use hw_chain::Chain;
use prost::Message;

use super::{EncodedMessage, ProtoMappingError};
use crate::thp::types::{
    GetAddressRequest, GetAddressResponse, SignMessageRequest, SignMessageResponse, SignTxRequest,
    SignTypedDataPayload, SignTypedDataRequest, SignTypedDataResponse,
};

const MESSAGE_TYPE_ETHEREUM_GET_ADDRESS: u16 = 56;
const MESSAGE_TYPE_ETHEREUM_ADDRESS: u16 = 57;
const MESSAGE_TYPE_ETHEREUM_GET_PUBLIC_KEY: u16 = 450;
const MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY: u16 = 451;
pub const MESSAGE_TYPE_ETHEREUM_SIGN_MESSAGE: u16 = 64;
pub const MESSAGE_TYPE_ETHEREUM_MESSAGE_SIGNATURE: u16 = 66;
pub const MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_DATA: u16 = 464;
pub const MESSAGE_TYPE_ETHEREUM_TYPED_DATA_STRUCT_REQUEST: u16 = 465;
pub const MESSAGE_TYPE_ETHEREUM_TYPED_DATA_STRUCT_ACK: u16 = 466;
pub const MESSAGE_TYPE_ETHEREUM_TYPED_DATA_VALUE_REQUEST: u16 = 467;
pub const MESSAGE_TYPE_ETHEREUM_TYPED_DATA_VALUE_ACK: u16 = 468;
pub const MESSAGE_TYPE_ETHEREUM_TYPED_DATA_SIGNATURE: u16 = 469;
pub const MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_HASH: u16 = 470;
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
struct EthereumSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    message: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "3")]
    encoded_network: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "4")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumMessageSignature {
    #[prost(bytes = "vec", required, tag = "2")]
    signature: Vec<u8>,
    #[prost(string, required, tag = "3")]
    address: String,
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
struct EthereumSignTypedHash {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    domain_separator_hash: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "3")]
    message_hash: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    encoded_network: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumSignTypedData {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(string, required, tag = "2")]
    primary_type: String,
    #[prost(bool, optional, tag = "3")]
    metamask_v4_compat: Option<bool>,
    #[prost(message, optional, tag = "4")]
    definitions: Option<EthereumDefinitions>,
    #[prost(bytes = "vec", optional, tag = "5")]
    show_message_hash: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumDefinitions {
    #[prost(bytes = "vec", optional, tag = "1")]
    encoded_network: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    encoded_token: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTypedDataStructRequest {
    #[prost(string, required, tag = "1")]
    pub name: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTypedDataStructAck {
    #[prost(message, repeated, tag = "1")]
    pub members: Vec<EthereumStructMember>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumStructMember {
    #[prost(message, required, tag = "1")]
    pub field_type: EthereumFieldType,
    #[prost(string, required, tag = "2")]
    pub name: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumFieldType {
    #[prost(enumeration = "EthereumDataTypeProto", required, tag = "1")]
    pub data_type: i32,
    #[prost(uint32, optional, tag = "2")]
    pub size: Option<u32>,
    #[prost(message, optional, boxed, tag = "3")]
    pub entry_type: Option<Box<EthereumFieldType>>,
    #[prost(string, optional, tag = "4")]
    pub struct_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum EthereumDataTypeProto {
    Uint = 1,
    Int = 2,
    Bytes = 3,
    String = 4,
    Bool = 5,
    Address = 6,
    Array = 7,
    Struct = 8,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTypedDataValueRequest {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    pub member_path: Vec<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EthereumTypedDataValueAck {
    #[prost(bytes = "vec", required, tag = "1")]
    pub value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumTypedDataSignature {
    #[prost(bytes = "vec", required, tag = "1")]
    signature: Vec<u8>,
    #[prost(string, required, tag = "2")]
    address: String,
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

pub(super) fn encode_get_address_request(
    request: &GetAddressRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
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

pub(super) fn decode_get_address_response(
    message_type: u16,
    payload: &[u8],
) -> Result<GetAddressResponse, ProtoMappingError> {
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
        chain: Chain::Ethereum,
        address,
        mac: message.mac,
        public_key: None,
    })
}

pub(super) fn encode_get_public_key_request(
    path: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
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

pub(super) fn decode_get_public_key_response(
    message_type: u16,
    payload: &[u8],
) -> Result<String, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = EthereumPublicKey::decode(payload)?;
    message
        .xpub
        .ok_or(ProtoMappingError::UnexpectedMessage(message_type))
}

pub(super) fn encode_sign_message_request(
    request: &SignMessageRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = EthereumSignMessage {
        path: request.path.clone(),
        message: request.message.clone(),
        encoded_network: request.encoded_network.clone(),
        chunkify: Some(request.chunkify),
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_ETHEREUM_SIGN_MESSAGE,
        payload,
    })
}

pub(super) fn decode_sign_message_response(
    message_type: u16,
    payload: &[u8],
) -> Result<SignMessageResponse, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_ETHEREUM_MESSAGE_SIGNATURE {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = EthereumMessageSignature::decode(payload)?;
    Ok(SignMessageResponse {
        chain: Chain::Ethereum,
        address: message.address,
        signature: message.signature,
    })
}

pub(super) fn encode_sign_typed_data_request(
    request: &SignTypedDataRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    match &request.payload {
        SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            let message = EthereumSignTypedHash {
                path: request.path.clone(),
                domain_separator_hash: domain_separator_hash.clone(),
                message_hash: message_hash.clone(),
                encoded_network: request.encoded_network.clone(),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_HASH,
                payload,
            })
        }
        SignTypedDataPayload::TypedData(typed_data) => {
            let message = EthereumSignTypedData {
                path: request.path.clone(),
                primary_type: typed_data.primary_type.clone(),
                metamask_v4_compat: Some(typed_data.metamask_v4_compat),
                definitions: Some(EthereumDefinitions {
                    encoded_network: request.encoded_network.clone(),
                    encoded_token: None,
                }),
                show_message_hash: typed_data.show_message_hash.clone(),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_DATA,
                payload,
            })
        }
    }
}

#[derive(Debug, Clone)]
pub enum DecodedTypedDataResponse {
    StructRequest(EthereumTypedDataStructRequest),
    ValueRequest(EthereumTypedDataValueRequest),
    Signature(SignTypedDataResponse),
}

pub fn decode_sign_typed_data_message(
    message_type: u16,
    payload: &[u8],
) -> Result<DecodedTypedDataResponse, ProtoMappingError> {
    match message_type {
        MESSAGE_TYPE_ETHEREUM_TYPED_DATA_STRUCT_REQUEST => {
            let message = EthereumTypedDataStructRequest::decode(payload)?;
            Ok(DecodedTypedDataResponse::StructRequest(message))
        }
        MESSAGE_TYPE_ETHEREUM_TYPED_DATA_VALUE_REQUEST => {
            let message = EthereumTypedDataValueRequest::decode(payload)?;
            Ok(DecodedTypedDataResponse::ValueRequest(message))
        }
        MESSAGE_TYPE_ETHEREUM_TYPED_DATA_SIGNATURE => {
            let message = EthereumTypedDataSignature::decode(payload)?;
            Ok(DecodedTypedDataResponse::Signature(SignTypedDataResponse {
                chain: Chain::Ethereum,
                address: message.address,
                signature: message.signature,
            }))
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(message_type)),
    }
}

pub(super) fn decode_sign_typed_data_response(
    message_type: u16,
    payload: &[u8],
) -> Result<SignTypedDataResponse, ProtoMappingError> {
    match decode_sign_typed_data_message(message_type, payload)? {
        DecodedTypedDataResponse::Signature(response) => Ok(response),
        DecodedTypedDataResponse::StructRequest(_) | DecodedTypedDataResponse::ValueRequest(_) => {
            Err(ProtoMappingError::UnexpectedMessage(message_type))
        }
    }
}

pub fn encode_typed_data_struct_ack(
    ack: &EthereumTypedDataStructAck,
) -> Result<EncodedMessage, ProtoMappingError> {
    let mut payload = Vec::new();
    ack.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_ETHEREUM_TYPED_DATA_STRUCT_ACK,
        payload,
    })
}

pub fn encode_typed_data_value_ack(value: Vec<u8>) -> Result<EncodedMessage, ProtoMappingError> {
    let message = EthereumTypedDataValueAck { value };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_ETHEREUM_TYPED_DATA_VALUE_ACK,
        payload,
    })
}

pub(super) fn encode_sign_tx_request(
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
    use crate::thp::types::{
        Eip712StructMember, Eip712TypedData, GetAddressRequest, SignMessageRequest,
        SignTypedDataRequest,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

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
            decode_get_address_response(MESSAGE_TYPE_ETHEREUM_ADDRESS, &payload).unwrap();
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
            decode_get_address_response(MESSAGE_TYPE_ETHEREUM_ADDRESS, &payload).unwrap();
        assert_eq!(response.address, "0xdeadbeef");
    }

    #[test]
    fn decodes_ethereum_public_key_response() {
        let message = EthereumPublicKey {
            xpub: Some("xpub-test".into()),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key =
            decode_get_public_key_response(MESSAGE_TYPE_ETHEREUM_PUBLIC_KEY, &payload).unwrap();
        assert_eq!(public_key, "xpub-test");
    }

    #[test]
    fn encodes_sign_message_request() {
        let request = SignMessageRequest::ethereum(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            b"hello".to_vec(),
        )
        .with_chunkify(true);
        let encoded = encode_sign_message_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_SIGN_MESSAGE);

        let decoded = EthereumSignMessage::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.message, b"hello");
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn decodes_sign_message_response() {
        let message = EthereumMessageSignature {
            signature: vec![0x55; 65],
            address: "0xabc".to_string(),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let decoded =
            decode_sign_message_response(MESSAGE_TYPE_ETHEREUM_MESSAGE_SIGNATURE, &payload)
                .unwrap();
        assert_eq!(decoded.chain, Chain::Ethereum);
        assert_eq!(decoded.address, "0xabc");
        assert_eq!(decoded.signature.len(), 65);
    }

    #[test]
    fn encodes_sign_typed_data_hash_request() {
        let request = SignTypedDataRequest::ethereum(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            vec![0x11; 32],
            Some(vec![0x22; 32]),
        );
        let encoded = encode_sign_typed_data_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_HASH);

        let decoded = EthereumSignTypedHash::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.domain_separator_hash, vec![0x11; 32]);
        assert_eq!(decoded.message_hash, Some(vec![0x22; 32]));
    }

    #[test]
    fn encodes_sign_typed_data_full_request() {
        let mut types = BTreeMap::new();
        types.insert(
            "Mail".to_string(),
            vec![
                Eip712StructMember {
                    name: "from".into(),
                    type_name: "address".into(),
                },
                Eip712StructMember {
                    name: "contents".into(),
                    type_name: "string".into(),
                },
            ],
        );

        let typed_data = Eip712TypedData {
            types,
            primary_type: "Mail".to_string(),
            domain: json!({"name":"Demo"}),
            message: json!({"from":"0x0000000000000000000000000000000000000001","contents":"hi"}),
            metamask_v4_compat: true,
            show_message_hash: Some(vec![0x33; 32]),
        };
        let request = SignTypedDataRequest::ethereum_typed_data(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            typed_data,
        );
        let encoded = encode_sign_typed_data_request(&request).unwrap();
        assert_eq!(encoded.message_type, MESSAGE_TYPE_ETHEREUM_SIGN_TYPED_DATA);

        let decoded = EthereumSignTypedData::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.primary_type, "Mail");
        assert_eq!(decoded.metamask_v4_compat, Some(true));
        assert_eq!(decoded.show_message_hash, Some(vec![0x33; 32]));
    }

    #[test]
    fn decodes_sign_typed_data_signature_response() {
        let message = EthereumTypedDataSignature {
            signature: vec![0x77; 65],
            address: "0xdef".to_string(),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let decoded =
            decode_sign_typed_data_response(MESSAGE_TYPE_ETHEREUM_TYPED_DATA_SIGNATURE, &payload)
                .unwrap();
        assert_eq!(decoded.chain, Chain::Ethereum);
        assert_eq!(decoded.address, "0xdef");
        assert_eq!(decoded.signature.len(), 65);
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
