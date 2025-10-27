use std::convert::TryFrom;

use hex::{FromHex, ToHex};
use prost::Message;
use thiserror::Error;

use super::proto;
use super::types::{
    CredentialRequest, CredentialResponse, CreateSessionRequest, PairingMethod, PairingRequest,
    PairingRequestApproved, PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
    ThpProperties,
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

fn encode_message<M: Message>(message_type: proto::ThpMessageType, message: &M) -> Result<EncodedMessage, ProtoMappingError> {
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: message_type as i32 as u16,
        payload,
    })
}

pub fn encode_pairing_request(request: &PairingRequest) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpPairingRequest {
        host_name: request.host_name.clone(),
        app_name: request.app_name.clone(),
    };
    encode_message(proto::ThpMessageType::ThpPairingRequest, &message)
}

pub fn decode_pairing_request_approved(payload: &[u8]) -> Result<PairingRequestApproved, ProtoMappingError> {
    let _ = proto::ThpPairingRequestApproved::decode(payload)?;
    Ok(PairingRequestApproved)
}

pub fn encode_select_method(request: &SelectMethodRequest) -> Result<EncodedMessage, ProtoMappingError> {
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
                commitment: msg.commitment.unwrap_or_default(),
            })
        }
        proto::ThpMessageType::ThpPairingPreparationsFinished => {
            let _ = proto::ThpPairingPreparationsFinished::decode(payload)?;
            Ok(SelectMethodResponse::PairingPreparationsFinished { nfc_data: None })
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(message_type as i32 as u16)),
    }
}

pub fn encode_qr_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpQrCodeTag {
        tag: tag.to_string(),
    };
    encode_message(proto::ThpMessageType::ThpQrCodeTag, &message)
}

pub fn encode_nfc_tag(tag: &str) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpNfcTagHost {
        tag: tag.to_string(),
    };
    encode_message(proto::ThpMessageType::ThpNfcTagHost, &message)
}

pub fn encode_code_entry_tag(
    cpace_host_public_key: &[u8],
    tag: &[u8],
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpCodeEntryCpaceHostTag {
        cpace_host_public_key: Some(cpace_host_public_key.to_vec()),
        tag: Some(tag.to_vec()),
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
            Ok(ParsedTagResponse {
                secret: msg.secret.unwrap_or_default(),
            })
        }
        proto::ThpMessageType::ThpNfcTagTrezor => {
            let msg = proto::ThpNfcTagTrezor::decode(payload)?;
            Ok(ParsedTagResponse {
                secret: msg.tag.unwrap_or_default(),
            })
        }
        proto::ThpMessageType::ThpCodeEntrySecret => {
            let msg = proto::ThpCodeEntrySecret::decode(payload)?;
            Ok(ParsedTagResponse {
                secret: msg.secret.unwrap_or_default(),
            })
        }
        _ => Err(ProtoMappingError::UnexpectedMessage(message_type as i32 as u16)),
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
        .map(|v| match proto::ThpPairingMethod::from_i32(*v) {
            Some(proto::ThpPairingMethod::SkipPairing) => Ok(PairingMethod::SkipPairing),
            Some(proto::ThpPairingMethod::CodeEntry) => Ok(PairingMethod::CodeEntry),
            Some(proto::ThpPairingMethod::QrCode) => Ok(PairingMethod::QrCode),
            Some(proto::ThpPairingMethod::Nfc) => Ok(PairingMethod::Nfc),
            None => Err(ProtoMappingError::InvalidEnum(*v)),
        })
        .collect()
}

pub fn encode_credential_request(
    request: &CredentialRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpCredentialRequest {
        host_static_public_key: Some(request.host_static_public_key.clone()),
        autoconnect: Some(request.autoconnect),
        credential: request
            .credential
            .as_ref()
            .map(|cred| Vec::from_hex(cred))
            .transpose()?
            .map(Into::into),
    };
    encode_message(proto::ThpMessageType::ThpCredentialRequest, &message)
}

pub fn decode_credential_response(
    payload: &[u8],
) -> Result<CredentialResponse, ProtoMappingError> {
    let msg = proto::ThpCredentialResponse::decode(payload)?;
    let credential_bytes = msg
        .credential
        .unwrap_or_default()
        .into_bytes();

    Ok(CredentialResponse {
        trezor_static_public_key: msg
            .trezor_static_public_key
            .unwrap_or_default()
            .into_bytes(),
        credential: credential_bytes.encode_hex::<String>(),
        autoconnect: false,
    })
}

pub fn encode_end_request() -> Result<EncodedMessage, ProtoMappingError> {
    encode_message(proto::ThpMessageType::ThpEndRequest, &proto::ThpEndRequest {})
}

pub fn encode_create_session_request(
    request: &CreateSessionRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = proto::ThpCreateNewSession {
        passphrase: request.passphrase.clone(),
        on_device: Some(request.on_device),
        derive_cardano: Some(request.derive_cardano),
    };
    encode_message(proto::ThpMessageType::ThpCreateNewSession, &message)
}

pub fn decode_device_properties(
    payload: &[u8],
) -> Result<ThpDeviceProperties, ProtoMappingError> {
    let msg = proto::ThpDeviceProperties::decode(payload)?;
    let pairing_methods = proto_to_pairing_methods(&msg.pairing_methods)?;
    Ok(ThpDeviceProperties {
        internal_model: msg.internal_model,
        model_variant: msg.model_variant.unwrap_or(0),
        protocol_version_major: msg.protocol_version_major,
        protocol_version_minor: msg.protocol_version_minor,
        pairing_methods,
    })
}
*** End Patch
