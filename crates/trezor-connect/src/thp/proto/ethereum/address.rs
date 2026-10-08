use prost::Message;

use crate::thp::proto::wire::wire_messages;
use crate::thp::proto::{ProtoMappingError, WireMessage};
use crate::thp::types::{GetAddressRequest, GetAddressResponse, GetPublicKeyRequest};
use hw_chain::Chain;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumGetAddress {
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
pub(crate) struct EthereumAddress {
    #[prost(bytes = "vec", optional, tag = "1")]
    old_address: Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    address: Option<String>,
    #[prost(bytes = "vec", optional, tag = "3")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "2")]
    show_display: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumPublicKey {
    #[prost(string, optional, tag = "2")]
    pub(crate) xpub: Option<String>,
}

wire_messages! {
    EthereumGetAddress = 56,
    EthereumAddress = 57,
    EthereumGetPublicKey = 450,
    EthereumPublicKey = 451,
}

impl From<&GetAddressRequest> for EthereumGetAddress {
    fn from(request: &GetAddressRequest) -> Self {
        Self {
            path: request.path.clone(),
            show_display: Some(request.show_display),
            encoded_network: request.encoded_network.clone(),
            chunkify: Some(request.chunkify),
        }
    }
}

impl TryFrom<EthereumAddress> for GetAddressResponse {
    type Error = ProtoMappingError;

    fn try_from(message: EthereumAddress) -> Result<Self, Self::Error> {
        let address = message
            .address
            .or_else(|| {
                message
                    .old_address
                    .map(|bytes| format!("0x{}", hex::encode(bytes)))
            })
            .ok_or(ProtoMappingError::UnexpectedMessage(
                EthereumAddress::MESSAGE_TYPE,
            ))?;
        Ok(Self {
            chain: Chain::Ethereum,
            address,
            mac: message.mac,
            public_key: None,
        })
    }
}

impl From<&GetPublicKeyRequest> for EthereumGetPublicKey {
    fn from(request: &GetPublicKeyRequest) -> Self {
        Self {
            path: request.path.clone(),
            show_display: Some(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

    #[test]
    fn encodes_get_address_and_public_key() {
        let mut request = GetAddressRequest::ethereum(PATH.to_vec())
            .with_show_display(true)
            .with_chunkify(true);
        request.encoded_network = Some(vec![9, 9]);
        let encoded = request.encode();
        assert_eq!(encoded.message_type, EthereumGetAddress::MESSAGE_TYPE);
        let decoded = EthereumGetAddress::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.show_display, Some(true));
        assert_eq!(decoded.encoded_network, Some(vec![9, 9]));
        assert_eq!(decoded.chunkify, Some(true));

        let encoded = GetPublicKeyRequest::new(Chain::Ethereum, PATH.to_vec()).encode();
        assert_eq!(encoded.message_type, EthereumGetPublicKey::MESSAGE_TYPE);
        let decoded = EthereumGetPublicKey::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, PATH);
        assert_eq!(decoded.show_display, Some(false));
    }

    #[test]
    fn decodes_address_from_current_or_legacy_field() {
        let cases = [
            (Some("0x1234".to_string()), None, Some("0x1234")),
            (None, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]), Some("0xdeadbeef")),
            (None, None, None),
        ];
        for (address, old_address, expected) in cases {
            let payload = EthereumAddress {
                old_address,
                address,
                mac: Some(vec![0xAA, 0xBB]),
            }
            .encode_to_vec();
            let response = GetAddressResponse::decode(
                Chain::Ethereum,
                EthereumAddress::MESSAGE_TYPE,
                &payload,
            );
            match expected {
                Some(expected) => {
                    let response = response.unwrap();
                    assert_eq!(response.address, expected);
                    assert_eq!(response.mac, Some(vec![0xAA, 0xBB]));
                    assert!(response.public_key.is_none());
                }
                None => assert!(matches!(
                    response,
                    Err(ProtoMappingError::UnexpectedMessage(57))
                )),
            }
        }
    }

    #[test]
    fn decodes_public_key_and_rejects_missing_xpub() {
        let request = GetPublicKeyRequest::new(Chain::Ethereum, PATH.to_vec());
        let payload = EthereumPublicKey {
            xpub: Some("xpub-test".into()),
        }
        .encode_to_vec();
        assert_eq!(
            request
                .decode_response(EthereumPublicKey::MESSAGE_TYPE, &payload)
                .unwrap(),
            "xpub-test"
        );
        assert!(matches!(
            request.decode_response(EthereumPublicKey::MESSAGE_TYPE, &[]),
            Err(ProtoMappingError::UnexpectedMessage(451))
        ));
    }
}
