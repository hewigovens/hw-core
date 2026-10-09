use prost::Message;

use super::script_type::BitcoinInputScriptTypeProto;
use crate::thp::proto::wire::wire_messages;
use crate::thp::types::{GetAddressRequest, GetAddressResponse, GetPublicKeyRequest};
use hw_chain::Chain;

pub(super) const COIN_NAME: &str = "Bitcoin";

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinGetAddress {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(string, optional, tag = "2")]
    coin_name: Option<String>,
    #[prost(bool, optional, tag = "3")]
    show_display: Option<bool>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "5")]
    script_type: Option<i32>,
    #[prost(bool, optional, tag = "7")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinAddress {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", optional, tag = "2")]
    mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinGetPublicKey {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bool, optional, tag = "3")]
    show_display: Option<bool>,
    #[prost(string, optional, tag = "4")]
    coin_name: Option<String>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "5")]
    script_type: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinPublicKey {
    #[prost(string, required, tag = "2")]
    pub(crate) xpub: String,
}

wire_messages! {
    BitcoinGetPublicKey = 11,
    BitcoinPublicKey = 12,
    BitcoinGetAddress = 29,
    BitcoinAddress = 30,
}

impl From<&GetAddressRequest> for BitcoinGetAddress {
    fn from(request: &GetAddressRequest) -> Self {
        Self {
            path: request.path.clone(),
            coin_name: Some(COIN_NAME.to_string()),
            show_display: Some(request.show_display),
            script_type: BitcoinInputScriptTypeProto::wire_for_path(&request.path),
            chunkify: Some(request.chunkify),
        }
    }
}

impl From<BitcoinAddress> for GetAddressResponse {
    fn from(message: BitcoinAddress) -> Self {
        Self {
            chain: Chain::Bitcoin,
            address: message.address,
            mac: message.mac,
            public_key: None,
        }
    }
}

impl From<&GetPublicKeyRequest> for BitcoinGetPublicKey {
    fn from(request: &GetPublicKeyRequest) -> Self {
        Self {
            path: request.path.clone(),
            show_display: Some(false),
            coin_name: Some(COIN_NAME.to_string()),
            script_type: BitcoinInputScriptTypeProto::wire_for_path(&request.path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::proto::WireMessage;

    #[test]
    fn get_address_and_public_key_derive_script_type_from_path() {
        let cases = [
            (vec![], None),
            (
                vec![0x8000_002c, 0x8000_0000, 0x8000_0000, 0, 0],
                Some(BitcoinInputScriptTypeProto::SpendAddress),
            ),
            (
                vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0000],
                Some(BitcoinInputScriptTypeProto::SpendMultisig),
            ),
            (
                vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0001],
                Some(BitcoinInputScriptTypeProto::SpendP2ShWitness),
            ),
            (
                vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0002],
                Some(BitcoinInputScriptTypeProto::SpendWitness),
            ),
            (
                vec![0x8000_0030, 0x8000_0000, 0x8000_0000, 0x8000_0003],
                None,
            ),
            (vec![0x8000_0030, 0x8000_0000, 0x8000_0000], None),
            (
                vec![0x8000_0031, 0x8000_0000, 0x8000_0000, 0, 0],
                Some(BitcoinInputScriptTypeProto::SpendP2ShWitness),
            ),
            (
                vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
                Some(BitcoinInputScriptTypeProto::SpendWitness),
            ),
            (
                vec![0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 0],
                Some(BitcoinInputScriptTypeProto::SpendTaproot),
            ),
            (
                vec![0x8000_2729, 0x8000_0000, 0x8000_0000, 0, 0],
                Some(BitcoinInputScriptTypeProto::SpendTaproot),
            ),
            (vec![0x8000_0063, 0x8000_0000], None),
        ];
        for (path, expected) in cases {
            let expected = expected.map(|script_type| script_type as i32);
            let request = GetAddressRequest::bitcoin(path.clone())
                .with_show_display(true)
                .with_chunkify(true);
            let encoded = request.encode();
            assert_eq!(encoded.message_type, BitcoinGetAddress::MESSAGE_TYPE);
            let decoded = BitcoinGetAddress::decode(encoded.payload.as_slice()).unwrap();
            assert_eq!(decoded.path, path);
            assert_eq!(decoded.coin_name.as_deref(), Some(COIN_NAME));
            assert_eq!(decoded.show_display, Some(true));
            assert_eq!(decoded.chunkify, Some(true));
            assert_eq!(decoded.script_type, expected, "address {path:?}");

            let encoded = GetPublicKeyRequest::new(Chain::Bitcoin, path.clone()).encode();
            assert_eq!(encoded.message_type, BitcoinGetPublicKey::MESSAGE_TYPE);
            let decoded = BitcoinGetPublicKey::decode(encoded.payload.as_slice()).unwrap();
            assert_eq!(decoded.show_display, Some(false));
            assert_eq!(decoded.coin_name.as_deref(), Some(COIN_NAME));
            assert_eq!(decoded.script_type, expected, "public key {path:?}");
        }
    }

    #[test]
    fn decodes_address_and_public_key_responses() {
        let payload = BitcoinAddress {
            address: "bc1qtest".into(),
            mac: Some(vec![0xAA, 0xBB]),
        }
        .encode_to_vec();
        let response =
            GetAddressResponse::decode(Chain::Bitcoin, BitcoinAddress::MESSAGE_TYPE, &payload)
                .unwrap();
        assert_eq!(response.chain, Chain::Bitcoin);
        assert_eq!(response.address, "bc1qtest");
        assert_eq!(response.mac, Some(vec![0xAA, 0xBB]));
        assert!(response.public_key.is_none());

        let payload = BitcoinPublicKey {
            xpub: "xpub6CUGRU".into(),
        }
        .encode_to_vec();
        let request = GetPublicKeyRequest::new(Chain::Bitcoin, Vec::new());
        let public_key = request
            .decode_response(BitcoinPublicKey::MESSAGE_TYPE, &payload)
            .unwrap();
        assert_eq!(public_key, "xpub6CUGRU");
    }
}
