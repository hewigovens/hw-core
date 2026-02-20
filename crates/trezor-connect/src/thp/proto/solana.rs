use bs58::encode as base58_encode;
use hw_chain::Chain;
use prost::Message;

use super::{EncodedMessage, ProtoMappingError};
use crate::thp::types::{GetAddressRequest, GetAddressResponse, SignTxRequest};

const MESSAGE_TYPE_SOLANA_GET_PUBLIC_KEY: u16 = 900;
const MESSAGE_TYPE_SOLANA_PUBLIC_KEY: u16 = 901;
const MESSAGE_TYPE_SOLANA_GET_ADDRESS: u16 = 902;
const MESSAGE_TYPE_SOLANA_ADDRESS: u16 = 903;
pub const MESSAGE_TYPE_SOLANA_SIGN_TX: u16 = 904;
pub const MESSAGE_TYPE_SOLANA_TX_SIGNATURE: u16 = 905;

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

pub(super) fn encode_get_address_request(
    request: &GetAddressRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
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

pub(super) fn decode_get_address_response(
    message_type: u16,
    payload: &[u8],
) -> Result<GetAddressResponse, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_SOLANA_ADDRESS {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = SolanaAddress::decode(payload)?;
    Ok(GetAddressResponse {
        chain: Chain::Solana,
        address: message.address,
        mac: message.mac,
        public_key: None,
    })
}

pub(super) fn encode_get_public_key_request(
    path: &[u32],
    show_display: bool,
) -> Result<EncodedMessage, ProtoMappingError> {
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

pub(super) fn decode_get_public_key_response(
    message_type: u16,
    payload: &[u8],
) -> Result<String, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_SOLANA_PUBLIC_KEY {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = SolanaPublicKey::decode(payload)?;
    Ok(base58_encode(message.public_key).into_string())
}

pub(super) fn encode_sign_tx_request(
    request: &SignTxRequest,
) -> Result<(EncodedMessage, usize), ProtoMappingError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::types::GetAddressRequest;

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
    fn decodes_solana_address_response() {
        let message = SolanaAddress {
            address: "So1anaAddress".into(),
            mac: Some(vec![0x11, 0x22]),
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let response = decode_get_address_response(MESSAGE_TYPE_SOLANA_ADDRESS, &payload).unwrap();
        assert_eq!(response.address, "So1anaAddress");
        assert_eq!(response.mac, Some(vec![0x11, 0x22]));
        assert!(response.public_key.is_none());
    }

    #[test]
    fn decodes_solana_public_key_response_as_base58() {
        let message = SolanaPublicKey {
            public_key: vec![1, 2, 3, 4, 5],
        };
        let mut payload = Vec::new();
        message.encode(&mut payload).unwrap();

        let public_key =
            decode_get_public_key_response(MESSAGE_TYPE_SOLANA_PUBLIC_KEY, &payload).unwrap();
        assert_eq!(public_key, "7bWpTW");
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
}
