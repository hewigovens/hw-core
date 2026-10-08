use bs58::encode as base58_encode;
use hw_chain::Chain;
use prost::Message;

use super::{EncodedMessage, ProtoMappingError};
use crate::thp::types::{
    GetAddressRequest, GetAddressResponse, SignMessageRequest, SignMessageResponse, SignTxRequest,
};

const MESSAGE_TYPE_SOLANA_GET_PUBLIC_KEY: u16 = 900;
const MESSAGE_TYPE_SOLANA_PUBLIC_KEY: u16 = 901;
const MESSAGE_TYPE_SOLANA_GET_ADDRESS: u16 = 902;
const MESSAGE_TYPE_SOLANA_ADDRESS: u16 = 903;
pub const MESSAGE_TYPE_SOLANA_SIGN_TX: u16 = 904;
pub const MESSAGE_TYPE_SOLANA_TX_SIGNATURE: u16 = 905;
const MESSAGE_TYPE_SOLANA_SIGN_MESSAGE: u16 = 906;
const MESSAGE_TYPE_SOLANA_MESSAGE_SIGNATURE: u16 = 907;

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

#[derive(Clone, PartialEq, Message)]
struct SolanaOffchainMessageV1 {
    #[prost(string, required, tag = "1")]
    message: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    signers: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "3")]
    chunkify: Option<bool>,
    #[prost(message, required, tag = "4")]
    message: SolanaOffchainMessageV1,
}

#[derive(Clone, PartialEq, Message)]
struct SolanaMessageSignature {
    #[prost(bytes = "vec", required, tag = "1")]
    signature: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signed_data: Option<Vec<u8>>,
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

pub(super) fn encode_sign_message_request(
    request: &SignMessageRequest,
) -> Result<EncodedMessage, ProtoMappingError> {
    let message = SolanaSignMessage {
        path: request.path.clone(),
        chunkify: Some(request.chunkify),
        message: SolanaOffchainMessageV1 {
            message: String::from_utf8(request.message.clone())?,
            signers: request
                .solana_signers
                .iter()
                .map(|signer| signer.to_vec())
                .collect(),
        },
    };
    let mut payload = Vec::new();
    message.encode(&mut payload)?;
    Ok(EncodedMessage {
        message_type: MESSAGE_TYPE_SOLANA_SIGN_MESSAGE,
        payload,
    })
}

pub(super) fn decode_sign_message_response(
    message_type: u16,
    payload: &[u8],
) -> Result<SignMessageResponse, ProtoMappingError> {
    if message_type != MESSAGE_TYPE_SOLANA_MESSAGE_SIGNATURE {
        return Err(ProtoMappingError::UnexpectedMessage(message_type));
    }
    let message = SolanaMessageSignature::decode(payload)?;
    Ok(SignMessageResponse {
        chain: Chain::Solana,
        address: String::new(),
        signature: message.signature,
        signed_data: message.signed_data,
    })
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

    // Suite e2e fixture solanaSignMessage "m/44'/501'/0'/0' sign 'Hello, Trezor!'" (mnemonic_all).
    const SUITE_SIGNER_HEX: &str =
        "00d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad";
    const SUITE_SIGNATURE_HEX: &str = "f2580d7f82bf2f9737925e7817d5b04cfe8b5e9b1f3c138517a9c55f2bb1f95524db937ec2a1dfebf67a1dc3ab27ef80629854ee2af5cb0ceb40568bc1bdb503";
    const SUITE_SIGNED_DATA_HEX: &str = "ff736f6c616e61206f6666636861696e010100d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad48656c6c6f2c205472657a6f7221";

    #[test]
    fn encodes_solana_sign_message_request_as_ocms_v1() {
        let signer: [u8; 32] = hex::decode(SUITE_SIGNER_HEX).unwrap().try_into().unwrap();
        let request = SignMessageRequest::solana(
            vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000],
            "Hello, Trezor!".into(),
            vec![signer],
        );
        let encoded = encode_sign_message_request(&request).unwrap();

        assert_eq!(encoded.message_type, MESSAGE_TYPE_SOLANA_SIGN_MESSAGE);
        assert_eq!(
            hex::encode(&encoded.payload),
            format!(
                "08ac80808008\
                 08f583808008\
                 088080808008\
                 088080808008\
                 1800\
                 2232\
                 0a0e48656c6c6f2c205472657a6f7221\
                 1220{SUITE_SIGNER_HEX}"
            )
        );
    }

    #[test]
    fn rejects_non_utf8_solana_message() {
        let mut request = SignMessageRequest::solana(vec![0x8000_002c], String::new(), vec![]);
        request.message = vec![0xff, 0xfe];

        let err = encode_sign_message_request(&request).unwrap_err();
        assert!(matches!(err, ProtoMappingError::InvalidUtf8(_)));
    }

    #[test]
    fn decodes_solana_message_signature_with_signed_data() {
        let payload = hex::decode(format!(
            "0a40{SUITE_SIGNATURE_HEX}1240{SUITE_SIGNED_DATA_HEX}"
        ))
        .unwrap();

        let response =
            decode_sign_message_response(MESSAGE_TYPE_SOLANA_MESSAGE_SIGNATURE, &payload).unwrap();
        assert_eq!(response.chain, Chain::Solana);
        assert!(response.address.is_empty());
        assert_eq!(hex::encode(&response.signature), SUITE_SIGNATURE_HEX);
        assert_eq!(
            response.signed_data.map(hex::encode).as_deref(),
            Some(SUITE_SIGNED_DATA_HEX)
        );
    }
}
