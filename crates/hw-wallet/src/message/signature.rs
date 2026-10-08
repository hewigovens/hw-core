use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hw_chain::Chain;
use trezor_connect::thp::SignMessageResponse;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignatureEncoding {
    Hex,
    Base64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NormalizedMessageSignature {
    pub encoding: SignatureEncoding,
    pub value: String,
}

impl From<&SignMessageResponse> for NormalizedMessageSignature {
    fn from(response: &SignMessageResponse) -> Self {
        let (encoding, value) = match response.chain {
            Chain::Bitcoin => (
                SignatureEncoding::Base64,
                BASE64.encode(&response.signature),
            ),
            Chain::Ethereum => (
                SignatureEncoding::Hex,
                format!("0x{}", hex::encode(&response.signature)),
            ),
            Chain::Solana => (SignatureEncoding::Hex, hex::encode(&response.signature)),
        };
        Self { encoding, value }
    }
}
