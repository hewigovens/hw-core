use hw_chain::Chain;
use prost::Message;

use super::ProtoMappingError;
use super::wire::wire_messages;
use crate::thp::types::{
    GetAddressRequest, GetAddressResponse, GetPublicKeyRequest, SignMessageRequest,
    SignMessageResponse, SignTxRequest,
};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaPublicKey {
    #[prost(bytes = "vec", required, tag = "1")]
    pub(crate) public_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaGetAddress {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
    #[prost(bool, optional, tag = "3")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaAddress {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaSignTx {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    serialized_tx: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct SolanaTxSignature {
    #[prost(bytes = "vec", required, tag = "1")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaOffchainMessageV1 {
    #[prost(string, required, tag = "1")]
    message: String,
    #[prost(bytes = "vec", repeated, tag = "2")]
    signers: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "3")]
    chunkify: Option<bool>,
    #[prost(message, required, tag = "4")]
    message: SolanaOffchainMessageV1,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct SolanaMessageSignature {
    #[prost(bytes = "vec", required, tag = "1")]
    signature: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "2")]
    signed_data: Option<Vec<u8>>,
}

wire_messages! {
    SolanaGetPublicKey = 900,
    SolanaPublicKey = 901,
    SolanaGetAddress = 902,
    SolanaAddress = 903,
    SolanaSignTx = 904,
    SolanaTxSignature = 905,
    SolanaSignMessage = 906,
    SolanaMessageSignature = 907,
}

impl From<&GetAddressRequest> for SolanaGetAddress {
    fn from(request: &GetAddressRequest) -> Self {
        Self {
            path: request.path.clone(),
            show_display: Some(request.show_display),
            chunkify: Some(request.chunkify),
        }
    }
}

impl From<SolanaAddress> for GetAddressResponse {
    fn from(message: SolanaAddress) -> Self {
        Self {
            chain: Chain::Solana,
            address: message.address,
            mac: message.mac,
            public_key: None,
        }
    }
}

impl From<&GetPublicKeyRequest> for SolanaGetPublicKey {
    fn from(request: &GetPublicKeyRequest) -> Self {
        Self {
            path: request.path.clone(),
            show_display: Some(false),
        }
    }
}

impl From<&SignTxRequest> for SolanaSignTx {
    fn from(request: &SignTxRequest) -> Self {
        Self {
            path: request.path.clone(),
            serialized_tx: request.data.clone(),
        }
    }
}

impl TryFrom<&SignMessageRequest> for SolanaSignMessage {
    type Error = ProtoMappingError;

    fn try_from(request: &SignMessageRequest) -> Result<Self, Self::Error> {
        Ok(Self {
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
        })
    }
}

impl From<SolanaMessageSignature> for SignMessageResponse {
    fn from(message: SolanaMessageSignature) -> Self {
        Self {
            chain: Chain::Solana,
            address: String::new(),
            signature: message.signature,
            signed_data: message.signed_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::proto::WireMessage;

    const PATH: [u32; 4] = [0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000];

    #[test]
    fn encodes_get_address_and_public_key() {
        let request = GetAddressRequest::solana(PATH.to_vec())
            .with_show_display(true)
            .with_chunkify(true);
        let encoded = request.encode();
        assert_eq!(encoded.message_type, SolanaGetAddress::MESSAGE_TYPE);
        let decoded = SolanaGetAddress::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.chunkify, Some(true));

        let encoded = GetPublicKeyRequest::new(Chain::Solana, PATH.to_vec()).encode();
        assert_eq!(encoded.message_type, SolanaGetPublicKey::MESSAGE_TYPE);
        let decoded = SolanaGetPublicKey::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.show_display, Some(false));
    }

    #[test]
    fn decodes_address_and_base58_public_key() {
        let payload = SolanaAddress {
            address: "So1anaAddress".into(),
            mac: Some(vec![0x11, 0x22]),
        }
        .encode_to_vec();
        let response =
            GetAddressResponse::decode(Chain::Solana, SolanaAddress::MESSAGE_TYPE, &payload)
                .unwrap();
        assert_eq!(response.chain, Chain::Solana);
        assert_eq!(response.address, "So1anaAddress");
        assert_eq!(response.mac, Some(vec![0x11, 0x22]));
        assert!(response.public_key.is_none());

        let payload = SolanaPublicKey {
            public_key: vec![1, 2, 3, 4, 5],
        }
        .encode_to_vec();
        let request = GetPublicKeyRequest::new(Chain::Solana, PATH.to_vec());
        assert_eq!(
            request
                .decode_response(SolanaPublicKey::MESSAGE_TYPE, &payload)
                .unwrap(),
            "7bWpTW"
        );
    }

    #[test]
    fn encodes_sign_tx_and_decodes_signature() {
        let request = SignTxRequest::solana(PATH.to_vec(), vec![0xAA, 0xBB, 0xCC]);
        let (encoded, offset) = request.encode().unwrap();
        assert_eq!(encoded.message_type, SolanaSignTx::MESSAGE_TYPE);
        assert_eq!(offset, 0);
        let decoded = SolanaSignTx::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.serialized_tx, vec![0xAA, 0xBB, 0xCC]);

        let payload = SolanaTxSignature {
            signature: vec![0x11; 64],
        }
        .encode_to_vec();
        let signature =
            SolanaTxSignature::from_message(SolanaTxSignature::MESSAGE_TYPE, &payload).unwrap();
        assert_eq!(signature.signature, vec![0x11; 64]);
    }

    // Suite e2e fixture solanaSignMessage "m/44'/501'/0'/0' sign 'Hello, Trezor!'" (mnemonic_all).
    const SUITE_SIGNER_HEX: &str =
        "00d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad";
    const SUITE_SIGNATURE_HEX: &str = "f2580d7f82bf2f9737925e7817d5b04cfe8b5e9b1f3c138517a9c55f2bb1f95524db937ec2a1dfebf67a1dc3ab27ef80629854ee2af5cb0ceb40568bc1bdb503";
    const SUITE_SIGNED_DATA_HEX: &str = "ff736f6c616e61206f6666636861696e010100d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad48656c6c6f2c205472657a6f7221";

    #[test]
    fn encodes_solana_sign_message_request_as_ocms_v1() {
        let signer: [u8; 32] = hex::decode(SUITE_SIGNER_HEX).unwrap().try_into().unwrap();
        let request =
            SignMessageRequest::solana(PATH.to_vec(), "Hello, Trezor!".into(), vec![signer]);
        let encoded = request.encode().unwrap();

        assert_eq!(encoded.message_type, SolanaSignMessage::MESSAGE_TYPE);
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

        let err = request.encode().unwrap_err();
        assert!(matches!(err, ProtoMappingError::InvalidUtf8(_)));
    }

    #[test]
    fn decodes_solana_message_signature_with_signed_data() {
        let payload = hex::decode(format!(
            "0a40{SUITE_SIGNATURE_HEX}1240{SUITE_SIGNED_DATA_HEX}"
        ))
        .unwrap();

        let response = SignMessageResponse::decode(
            Chain::Solana,
            SolanaMessageSignature::MESSAGE_TYPE,
            &payload,
        )
        .unwrap();
        assert_eq!(response.chain, Chain::Solana);
        assert!(response.address.is_empty());
        assert_eq!(hex::encode(&response.signature), SUITE_SIGNATURE_HEX);
        assert_eq!(
            response.signed_data.map(hex::encode).as_deref(),
            Some(SUITE_SIGNED_DATA_HEX)
        );
    }
}
