use prost::Message;

use crate::thp::proto::wire::wire_messages;
use crate::thp::types::{SignMessageRequest, SignMessageResponse};
use hw_chain::Chain;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumSignMessage {
    #[prost(uint32, repeated, packed = "false", tag = "1")]
    path: Vec<u32>,
    #[prost(bytes = "vec", required, tag = "2")]
    message: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "3")]
    encoded_network: Option<Vec<u8>>,
    #[prost(bool, optional, tag = "4")]
    chunkify: Option<bool>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumMessageSignature {
    #[prost(bytes = "vec", required, tag = "2")]
    signature: Vec<u8>,
    #[prost(string, required, tag = "3")]
    address: String,
}

wire_messages! {
    EthereumSignMessage = 64,
    EthereumMessageSignature = 66,
}

impl From<&SignMessageRequest> for EthereumSignMessage {
    fn from(request: &SignMessageRequest) -> Self {
        Self {
            path: request.path.clone(),
            message: request.message.clone(),
            encoded_network: request.encoded_network.clone(),
            chunkify: Some(request.chunkify),
        }
    }
}

impl From<EthereumMessageSignature> for SignMessageResponse {
    fn from(message: EthereumMessageSignature) -> Self {
        Self {
            chain: Chain::Ethereum,
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
    fn encodes_sign_message_request() {
        let mut request = SignMessageRequest::ethereum(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            b"hello".to_vec(),
        )
        .with_chunkify(true);
        request.encoded_network = Some(vec![1]);
        let encoded = request.encode().unwrap();
        assert_eq!(encoded.message_type, EthereumSignMessage::MESSAGE_TYPE);

        let decoded = EthereumSignMessage::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.path, request.path);
        assert_eq!(decoded.message, b"hello");
        assert_eq!(decoded.encoded_network, Some(vec![1]));
        assert_eq!(decoded.chunkify, Some(true));
    }

    #[test]
    fn decodes_sign_message_response() {
        let payload = EthereumMessageSignature {
            signature: vec![0x55; 65],
            address: "0xabc".to_string(),
        }
        .encode_to_vec();

        let decoded = SignMessageResponse::decode(
            Chain::Ethereum,
            EthereumMessageSignature::MESSAGE_TYPE,
            &payload,
        )
        .unwrap();
        assert_eq!(decoded.chain, Chain::Ethereum);
        assert_eq!(decoded.address, "0xabc");
        assert_eq!(decoded.signature.len(), 65);
        assert!(decoded.signed_data.is_none());
    }
}
