use std::convert::TryFrom;

use hex::{FromHex, ToHex};
use prost::Message;
use thiserror::Error;

use super::proto;
use super::types::{
    Chain, CodeEntryChallengeResponse, CredentialRequest, CredentialResponse, GetAddressRequest,
    GetAddressResponse, PairingMethod, PairingRequest, PairingRequestApproved, PairingTagResponse,
    SelectMethodRequest, SelectMethodResponse, ThpProperties,
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

#[derive(Clone, PartialEq, Message)]
struct EthereumGetAddressProto {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    address_n: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
    #[prost(bytes = "vec", optional, tag = "3")]
    encoded_network: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "4")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumAddressProto {
    #[prost(bytes = "vec", optional, tag = "1")]
    old_address: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumGetPublicKeyProto {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    address_n: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
struct EthereumPublicKeyProto {
    #[prost(string, optional, tag = "2")]
    xpub: Option<String>,
}

fn encode_message<M: Message>(
    message_type: proto::ThpMessageType,
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
    let message = proto::ThpPairingRequest {
        host_name: request.host_name.clone(),
        app_name: request.app_name.clone(),
    };
    encode_message(proto::ThpMessageType::ThpPairingRequest, &message)
}

pub fn decode_pairing_request_approved(
    payload: &[u8],
) -> Result<PairingRequestApproved, ProtoMappingError> {
    let _ = proto::ThpPairingRequestApproved::decode(payload)?;
    Ok(PairingRequestApproved)
}

pub fn encode_select_method(
    request: &SelectMethodRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpSelectMethod {
        selected_pairing_method: pairing_method_to_proto(request.method),
    };
    encode_message(proto::ThpMessageType::ThpSelectMethod, &message)
}

pub fn decode_select_method_response(
    message_type: proto::ThpMessageType,
    payload: &[u8],
) -> Result<SelectMethodResponse, ProtoMappingError> {
    match message_type {
        proto::ThpMessageType::ThpEndResponse => {
            let _ = proto::ThpEndResponse::decode(payload)?;
            Ok(SelectMethodResponse::End)
        }
        proto::ThpMessageType::ThpCodeEntryCommitment => {
            let msg = proto::ThpCodeEntryCommitment::decode(payload)?;
            Ok(SelectMethodResponse::CodeEntryCommitment {
                commitment: msg.commitment,
            })
        }
        proto::ThpMessageType::ThpPairingPreparationsFinished => {
            let _ = proto::ThpPairingPreparationsFinished::decode(payload)?;
            Ok(SelectMethodResponse::PairingPreparationsFinished { nfc_data: None })
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(
            message_type as i32 as u16,
        )),
    }
}

pub fn encode_code_entry_challenge(challenge: &[u8]) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpCodeEntryChallenge {
        challenge: challenge.to_vec(),
    };
    encode_message(proto::ThpMessageType::ThpCodeEntryChallenge, &message)
}

pub fn decode_code_entry_cpace_response(
    payload: &[u8],
) -> Result<CodeEntryChallengeResponse, ProtoMappingError> {
    let msg = proto::ThpCodeEntryCpaceTrezor::decode(payload)?;
    Ok(CodeEntryChallengeResponse {
        trezor_cpace_public_key: msg.cpace_trezor_public_key,
    })
}

pub fn encode_qr_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpQrCodeTag {
        tag: Vec::from_hex(tag)?,
    };
    encode_message(proto::ThpMessageType::ThpQrCodeTag, &message)
}

pub fn encode_nfc_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpNfcTagHost {
        tag: Vec::from_hex(tag)?,
    };
    encode_message(proto::ThpMessageType::ThpNfcTagHost, &message)
}

pub fn encode_code_entry_tag(
    cpace_host_public_key: &[u8],
    tag: &[u8],
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpCodeEntryCpaceHostTag {
        cpace_host_public_key: cpace_host_public_key.to_vec(),
        tag: tag.to_vec(),
    };
    encode_message(proto::ThpMessageType::ThpCodeEntryCpaceHostTag, &message)
}

pub struct ParsedTagResponse {
    pub secret: Vec<u8>,
}

pub fn decode_tag_response(
    message_type: proto::ThpMessageType,
    payload: &[u8],
) -> Result<ParsedTagResponse, ProtoMappingError> {
    match message_type {
        proto::ThpMessageType::ThpQrCodeSecret => {
            let msg = proto::ThpQrCodeSecret::decode(payload)?;
            Ok(ParsedTagResponse { secret: msg.secret })
        }
        proto::ThpMessageType::ThpNfcTagTrezor => {
            let msg = proto::ThpNfcTagTrezor::decode(payload)?;
            Ok(ParsedTagResponse { secret: msg.tag })
        }
        proto::ThpMessageType::ThpCodeEntrySecret => {
            let msg = proto::ThpCodeEntrySecret::decode(payload)?;
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
        PairingMethod::SkipPairing => proto::ThpPairingMethod::SkipPairing as i32,
        PairingMethod::CodeEntry => proto::ThpPairingMethod::CodeEntry as i32,
        PairingMethod::QrCode => proto::ThpPairingMethod::QrCode as i32,
        PairingMethod::Nfc => proto::ThpPairingMethod::Nfc as i32,
    }
}

pub fn proto_to_pairing_methods(values: &[i32]) -> Result<Vec<PairingMethod>, ProtoMappingError> {
    values
        .iter()
        .map(|v| match proto::ThpPairingMethod::try_from(*v) {
            Ok(proto::ThpPairingMethod::SkipPairing) => Ok(PairingMethod::SkipPairing),
            Ok(proto::ThpPairingMethod::CodeEntry) => Ok(PairingMethod::CodeEntry),
            Ok(proto::ThpPairingMethod::QrCode) => Ok(PairingMethod::QrCode),
            Ok(proto::ThpPairingMethod::Nfc) => Ok(PairingMethod::Nfc),
            Err(_) => Err(ProtoMappingError::InvalidEnum(*v)),
        })
        .collect()
}

pub fn encode_credential_request(
    request: &CredentialRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let credential_bytes = request.credential.as_ref().map(Vec::from_hex).transpose()?;

    let message = proto::ThpCredentialRequest {
        host_static_public_key: request.host_static_public_key.clone(),
        autoconnect: Some(request.autoconnect),
        credential: credential_bytes,
    };
    encode_message(proto::ThpMessageType::ThpCredentialRequest, &message)
}

pub fn decode_credential_response(payload: &[u8]) -> Result<CredentialResponse, ProtoMappingError> {
    let msg = proto::ThpCredentialResponse::decode(payload)?;
    let credential_hex = msg.credential.encode_hex::<String>();

    Ok(CredentialResponse {
        trezor_static_public_key: msg.trezor_static_public_key,
        credential: credential_hex,
        autoconnect: false,
    })
}

pub fn encode_end_request() -> Result<EncodedMessage, ProtoMappingError> {
    encode_message(
        proto::ThpMessageType::ThpEndRequest,
        &proto::ThpEndRequest {},
    )
}

pub fn decode_device_properties(payload: &[u8]) -> Result<ThpProperties, ProtoMappingError> {
    let msg = proto::ThpDeviceProperties::decode(payload)?;
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
            let message = EthereumGetAddressProto {
                address_n: request.address_n.clone(),
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

            let message = EthereumAddressProto::decode(payload)?;
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
    }
}

pub fn encode_get_public_key_request(
    chain: Chain,
    address_n: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
    match chain {
        Chain::Ethereum => {
            let message = EthereumGetPublicKeyProto {
                address_n: address_n.to_vec(),
                show_display: Some(show_display),
            };
            let mut payload = Vec::new();
            message.encode(&mut payload)?;
            Ok(EncodedMessage {
                message_type: MESSAGE_TYPE_ETHEREUM_GET_PUBLIC_KEY,
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
            let message = EthereumPublicKeyProto::decode(payload)?;
            message
                .xpub
                .ok_or(ProtoMappingError::UnexpectedMessage(message_type))
        }
    }
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

        let decoded = EthereumGetAddressProto::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.address_n, request.address_n);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn decodes_ethereum_address_response_with_mac() {
        let message = EthereumAddressProto {
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
        let message = EthereumAddressProto {
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
        let message = EthereumPublicKeyProto {
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
}
