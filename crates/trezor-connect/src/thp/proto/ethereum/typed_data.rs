use prost::Message;

use crate::thp::proto::wire::wire_messages;
use crate::thp::proto::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::types::{SignTypedDataPayload, SignTypedDataRequest, SignTypedDataResponse};
use hw_chain::Chain;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumSignTypedHash {
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
pub(crate) struct EthereumSignTypedData {
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
pub(crate) struct EthereumDefinitions {
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
pub(crate) struct EthereumTypedDataSignature {
    #[prost(bytes = "vec", required, tag = "1")]
    signature: Vec<u8>,
    #[prost(string, required, tag = "2")]
    address: String,
}

wire_messages! {
    EthereumSignTypedData = 464,
    EthereumTypedDataStructRequest = 465,
    EthereumTypedDataStructAck = 466,
    EthereumTypedDataValueRequest = 467,
    EthereumTypedDataValueAck = 468,
    EthereumTypedDataSignature = 469,
    EthereumSignTypedHash = 470,
}

impl SignTypedDataRequest {
    pub fn encode(&self) -> Result<EncodedMessage, ProtoMappingError> {
        if self.chain != Chain::Ethereum {
            return Err(ProtoMappingError::UnsupportedChain(self.chain));
        }
        Ok(match &self.payload {
            SignTypedDataPayload::Hashes {
                domain_separator_hash,
                message_hash,
            } => EthereumSignTypedHash {
                path: self.path.clone(),
                domain_separator_hash: domain_separator_hash.clone(),
                message_hash: message_hash.clone(),
                encoded_network: self.encoded_network.clone(),
            }
            .to_message(),
            SignTypedDataPayload::TypedData(typed_data) => EthereumSignTypedData {
                path: self.path.clone(),
                primary_type: typed_data.primary_type.clone(),
                metamask_v4_compat: Some(typed_data.metamask_v4_compat),
                definitions: Some(EthereumDefinitions {
                    encoded_network: self.encoded_network.clone(),
                    encoded_token: None,
                }),
                show_message_hash: typed_data.show_message_hash.clone(),
            }
            .to_message(),
        })
    }
}

/// A device message during EIP-712 signing: a type or value request, or the final signature.
#[derive(Debug, Clone)]
pub enum DecodedTypedDataResponse {
    StructRequest(EthereumTypedDataStructRequest),
    ValueRequest(EthereumTypedDataValueRequest),
    Signature(SignTypedDataResponse),
}

impl DecodedTypedDataResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        match message_type {
            EthereumTypedDataStructRequest::MESSAGE_TYPE => Ok(Self::StructRequest(
                EthereumTypedDataStructRequest::decode(payload)?,
            )),
            EthereumTypedDataValueRequest::MESSAGE_TYPE => Ok(Self::ValueRequest(
                EthereumTypedDataValueRequest::decode(payload)?,
            )),
            EthereumTypedDataSignature::MESSAGE_TYPE => {
                let message = EthereumTypedDataSignature::decode(payload)?;
                Ok(Self::Signature(SignTypedDataResponse {
                    chain: Chain::Ethereum,
                    address: message.address,
                    signature: message.signature,
                }))
            }
            _ => Err(ProtoMappingError::UnexpectedMessage(message_type)),
        }
    }
}

impl SignTypedDataResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        match DecodedTypedDataResponse::decode(message_type, payload)? {
            DecodedTypedDataResponse::Signature(response) => Ok(response),
            DecodedTypedDataResponse::StructRequest(_)
            | DecodedTypedDataResponse::ValueRequest(_) => {
                Err(ProtoMappingError::UnexpectedMessage(message_type))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::{Eip712StructMember, Eip712TypedData};
    use serde_json::json;
    use std::collections::BTreeMap;

    const PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

    #[test]
    fn encodes_sign_typed_hash_request() {
        let mut request =
            SignTypedDataRequest::ethereum(PATH.to_vec(), vec![0x11; 32], Some(vec![0x22; 32]));
        request.encoded_network = Some(vec![5]);
        let encoded = request.encode().unwrap();
        assert_eq!(encoded.message_type, EthereumSignTypedHash::MESSAGE_TYPE);

        let decoded = EthereumSignTypedHash::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.domain_separator_hash, vec![0x11; 32]);
        assert_eq!(decoded.message_hash, Some(vec![0x22; 32]));
        assert_eq!(decoded.encoded_network, Some(vec![5]));
    }

    #[test]
    fn encodes_sign_typed_data_request_and_rejects_other_chains() {
        let typed_data = Eip712TypedData {
            types: BTreeMap::from([(
                "Mail".to_string(),
                vec![Eip712StructMember {
                    name: "contents".into(),
                    type_name: "string".into(),
                }],
            )]),
            primary_type: "Mail".to_string(),
            domain: json!({"name": "Demo"}),
            message: json!({"contents": "hi"}),
            metamask_v4_compat: true,
            show_message_hash: Some(vec![0x33; 32]),
        };
        let mut request = SignTypedDataRequest::ethereum_typed_data(PATH.to_vec(), typed_data);
        request.encoded_network = Some(vec![6]);
        let encoded = request.encode().unwrap();
        assert_eq!(encoded.message_type, EthereumSignTypedData::MESSAGE_TYPE);

        let decoded = EthereumSignTypedData::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.primary_type, "Mail");
        assert_eq!(decoded.metamask_v4_compat, Some(true));
        assert_eq!(decoded.show_message_hash, Some(vec![0x33; 32]));
        let definitions = decoded.definitions.unwrap();
        assert_eq!(definitions.encoded_network, Some(vec![6]));
        assert!(definitions.encoded_token.is_none());

        request.chain = Chain::Solana;
        assert!(matches!(
            request.encode(),
            Err(ProtoMappingError::UnsupportedChain(Chain::Solana))
        ));
    }

    #[test]
    fn decodes_typed_data_device_messages() {
        let struct_request = EthereumTypedDataStructRequest {
            name: "Mail".into(),
        }
        .encode_to_vec();
        let value_request = EthereumTypedDataValueRequest {
            member_path: vec![1, 0],
        }
        .encode_to_vec();
        let signature = EthereumTypedDataSignature {
            signature: vec![0x77; 65],
            address: "0xdef".to_string(),
        }
        .encode_to_vec();

        assert!(matches!(
            DecodedTypedDataResponse::decode(EthereumTypedDataStructRequest::MESSAGE_TYPE, &struct_request),
            Ok(DecodedTypedDataResponse::StructRequest(request)) if request.name == "Mail"
        ));
        assert!(matches!(
            DecodedTypedDataResponse::decode(EthereumTypedDataValueRequest::MESSAGE_TYPE, &value_request),
            Ok(DecodedTypedDataResponse::ValueRequest(request)) if request.member_path == [1, 0]
        ));
        let response =
            SignTypedDataResponse::decode(EthereumTypedDataSignature::MESSAGE_TYPE, &signature)
                .unwrap();
        assert_eq!(response.chain, Chain::Ethereum);
        assert_eq!(response.address, "0xdef");
        assert_eq!(response.signature.len(), 65);

        assert!(matches!(
            SignTypedDataResponse::decode(
                EthereumTypedDataStructRequest::MESSAGE_TYPE,
                &struct_request
            ),
            Err(ProtoMappingError::UnexpectedMessage(465))
        ));
        assert!(matches!(
            DecodedTypedDataResponse::decode(EthereumTypedDataValueAck::MESSAGE_TYPE, &[]),
            Err(ProtoMappingError::UnexpectedMessage(468))
        ));
    }
}
