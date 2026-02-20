mod bitcoin;
mod ethereum;
mod solana;

use hex::{FromHex, ToHex};
use hw_chain::Chain;
use prost::Message;
use thiserror::Error;

use super::messages;
use super::types::{
    CodeEntryChallengeResponse, CredentialRequest, CredentialResponse, GetAddressRequest,
    GetAddressResponse, PairingMethod, PairingRequest, PairingRequestApproved, PairingTagResponse,
    SelectMethodRequest, SelectMethodResponse, SignMessageRequest, SignMessageResponse,
    SignTxRequest, SignTypedDataRequest, SignTypedDataResponse, ThpProperties,
};

pub use bitcoin::{
    BitcoinTxRequestType, DecodedBitcoinTxRequest, MESSAGE_TYPE_BITCOIN_SIGN_TX,
    MESSAGE_TYPE_BITCOIN_TX_ACK, MESSAGE_TYPE_BITCOIN_TX_REQUEST, decode_bitcoin_tx_request,
    encode_bitcoin_tx_ack_input, encode_bitcoin_tx_ack_meta, encode_bitcoin_tx_ack_output,
    encode_bitcoin_tx_ack_prev_extra_data, encode_bitcoin_tx_ack_prev_input,
    encode_bitcoin_tx_ack_prev_meta, encode_bitcoin_tx_ack_prev_output,
};
pub use ethereum::{
    DecodedTypedDataResponse, ETH_DATA_CHUNK_SIZE, EthereumDataTypeProto, EthereumFieldType,
    EthereumStructMember, EthereumTxRequest, EthereumTypedDataStructAck,
    EthereumTypedDataStructRequest, EthereumTypedDataValueRequest,
    MESSAGE_TYPE_ETHEREUM_SIGN_TX_EIP1559, MESSAGE_TYPE_ETHEREUM_TX_ACK,
    MESSAGE_TYPE_ETHEREUM_TX_REQUEST, decode_tx_request, encode_tx_ack,
    encode_typed_data_struct_ack, encode_typed_data_value_ack,
};
pub use solana::{
    MESSAGE_TYPE_SOLANA_SIGN_TX, MESSAGE_TYPE_SOLANA_TX_SIGNATURE, decode_solana_tx_signature,
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
        Chain::Ethereum => ethereum::encode_get_address_request(request),
        Chain::Bitcoin => bitcoin::encode_get_address_request(request),
        Chain::Solana => solana::encode_get_address_request(request),
    }
}

pub fn decode_get_address_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<GetAddressResponse, ProtoMappingError> {
    match chain {
        Chain::Ethereum => ethereum::decode_get_address_response(message_type, payload),
        Chain::Bitcoin => bitcoin::decode_get_address_response(message_type, payload),
        Chain::Solana => solana::decode_get_address_response(message_type, payload),
    }
}

pub fn encode_get_public_key_request(
    chain: Chain,
    path: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
    match chain {
        Chain::Ethereum => ethereum::encode_get_public_key_request(path, show_display),
        Chain::Bitcoin => bitcoin::encode_get_public_key_request(path, show_display),
        Chain::Solana => solana::encode_get_public_key_request(path, show_display),
    }
}

pub fn decode_get_public_key_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<String, ProtoMappingError> {
    match chain {
        Chain::Ethereum => ethereum::decode_get_public_key_response(message_type, payload),
        Chain::Bitcoin => bitcoin::decode_get_public_key_response(message_type, payload),
        Chain::Solana => solana::decode_get_public_key_response(message_type, payload),
    }
}

pub fn encode_sign_tx_request(
    request: &SignTxRequest,
) -> Result<(EncodedMessage, usize), ProtoMappingError> {
    match request.chain {
        Chain::Ethereum => ethereum::encode_sign_tx_request(request),
        Chain::Bitcoin => bitcoin::encode_sign_tx_request(request),
        Chain::Solana => solana::encode_sign_tx_request(request),
    }
}

pub fn encode_sign_message_request(
    request: &SignMessageRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    match request.chain {
        Chain::Bitcoin => bitcoin::encode_sign_message_request(request),
        Chain::Ethereum => ethereum::encode_sign_message_request(request),
        Chain::Solana => Err(ProtoMappingError::UnsupportedChain(Chain::Solana)),
    }
}

pub fn decode_sign_message_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<SignMessageResponse, ProtoMappingError> {
    match chain {
        Chain::Bitcoin => bitcoin::decode_sign_message_response(message_type, payload),
        Chain::Ethereum => ethereum::decode_sign_message_response(message_type, payload),
        Chain::Solana => Err(ProtoMappingError::UnsupportedChain(Chain::Solana)),
    }
}

pub fn encode_sign_typed_data_request(
    request: &SignTypedDataRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    match request.chain {
        Chain::Ethereum => ethereum::encode_sign_typed_data_request(request),
        Chain::Bitcoin | Chain::Solana => Err(ProtoMappingError::UnsupportedChain(request.chain)),
    }
}

pub fn decode_sign_typed_data_response(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<SignTypedDataResponse, ProtoMappingError> {
    match chain {
        Chain::Ethereum => ethereum::decode_sign_typed_data_response(message_type, payload),
        Chain::Bitcoin | Chain::Solana => Err(ProtoMappingError::UnsupportedChain(chain)),
    }
}

pub fn decode_sign_typed_data_message(
    chain: Chain,
    message_type: u16,
    payload: &[u8],
) -> Result<DecodedTypedDataResponse, ProtoMappingError> {
    match chain {
        Chain::Ethereum => ethereum::decode_sign_typed_data_message(message_type, payload),
        Chain::Bitcoin | Chain::Solana => Err(ProtoMappingError::UnsupportedChain(chain)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::{BtcSignTx, GetAddressRequest};

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
    fn encode_sign_tx_dispatches_by_chain() {
        let eth = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_to("0xdead".into());
        let btc = SignTxRequest::bitcoin(BtcSignTx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            ref_txs: Vec::new(),
            chunkify: false,
        });
        let sol = SignTxRequest::solana(
            vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000],
            vec![1, 2, 3],
        );

        let (eth_msg, _) = encode_sign_tx_request(&eth).unwrap();
        let (btc_msg, _) = encode_sign_tx_request(&btc).unwrap();
        let (sol_msg, _) = encode_sign_tx_request(&sol).unwrap();

        assert_eq!(eth_msg.message_type, MESSAGE_TYPE_ETHEREUM_SIGN_TX_EIP1559);
        assert_eq!(btc_msg.message_type, MESSAGE_TYPE_BITCOIN_SIGN_TX);
        assert_eq!(sol_msg.message_type, MESSAGE_TYPE_SOLANA_SIGN_TX);
    }

    #[test]
    fn encode_get_address_dispatches_by_chain() {
        let eth = GetAddressRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]);
        let btc = GetAddressRequest::bitcoin(vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0]);
        let sol =
            GetAddressRequest::solana(vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]);

        let eth_msg = encode_get_address_request(&eth).unwrap();
        let btc_msg = encode_get_address_request(&btc).unwrap();
        let sol_msg = encode_get_address_request(&sol).unwrap();

        assert_eq!(eth_msg.message_type, 56);
        assert_eq!(btc_msg.message_type, 29);
        assert_eq!(sol_msg.message_type, 902);
    }
}
