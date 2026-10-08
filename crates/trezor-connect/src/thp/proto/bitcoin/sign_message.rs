use prost::Message;

use super::address::COIN_NAME;
use super::script_type::BitcoinInputScriptTypeProto;
use crate::thp::proto::wire::wire_messages;
use crate::thp::types::{BtcInputScriptType, SignMessageRequest, SignMessageResponse};
use hw_chain::Chain;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    message: Vec<u8>,
    #[prost(string, optional, tag = "3")]
    coin_name: Option<String>,
    #[prost(enumeration = "BitcoinInputScriptTypeProto", optional, tag = "4")]
    script_type: Option<i32>,
    #[prost(bool, optional, tag = "6")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct BitcoinMessageSignature {
    #[prost(string, required, tag = "1")]
    address: String,
    #[prost(bytes = "vec", required, tag = "2")]
    signature: Vec<u8>,
}

wire_messages! {
    BitcoinSignMessage = 38,
    BitcoinMessageSignature = 40,
}

impl From<&SignMessageRequest> for BitcoinSignMessage {
    fn from(request: &SignMessageRequest) -> Self {
        let script_type = BtcInputScriptType::from_path(&request.path)
            .unwrap_or(BtcInputScriptType::SpendAddress);
        Self {
            path: request.path.clone(),
            message: request.message.clone(),
            coin_name: Some(COIN_NAME.to_string()),
            script_type: Some(BitcoinInputScriptTypeProto::wire(script_type)),
            chunkify: Some(request.chunkify),
        }
    }
}

impl From<BitcoinMessageSignature> for SignMessageResponse {
    fn from(message: BitcoinMessageSignature) -> Self {
        Self {
            chain: Chain::Bitcoin,
            address: message.address,
            signature: message.signature,
            signed_data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::thp::proto::WireMessage;

    #[test]
    fn encodes_sign_message_with_path_script_type_or_spend_address() {
        let cases = [
            (
                vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
                BitcoinInputScriptTypeProto::SpendWitness,
            ),
            (
                vec![0x8000_0063, 0x8000_0000],
                BitcoinInputScriptTypeProto::SpendAddress,
            ),
        ];
        for (path, script_type) in cases {
            let request =
                SignMessageRequest::bitcoin(path.clone(), b"hello".to_vec()).with_chunkify(true);
            let encoded = request.encode().unwrap();
            assert_eq!(encoded.message_type, BitcoinSignMessage::MESSAGE_TYPE);

            let decoded = BitcoinSignMessage::decode(encoded.payload.as_slice()).unwrap();
            assert_eq!(decoded.path, path);
            assert_eq!(decoded.message, b"hello");
            assert_eq!(decoded.coin_name.as_deref(), Some(COIN_NAME));
            assert_eq!(decoded.script_type, Some(script_type as i32));
            assert_eq!(decoded.chunkify, Some(true));
        }
    }

    #[test]
    fn decodes_sign_message_response() {
        let payload = BitcoinMessageSignature {
            address: "bc1qtest".into(),
            signature: vec![0x99; 65],
        }
        .encode_to_vec();

        let response = SignMessageResponse::decode(
            Chain::Bitcoin,
            BitcoinMessageSignature::MESSAGE_TYPE,
            &payload,
        )
        .unwrap();
        assert_eq!(response.chain, Chain::Bitcoin);
        assert_eq!(response.address, "bc1qtest");
        assert_eq!(response.signature.len(), 65);
        assert!(response.signed_data.is_none());
    }
}
