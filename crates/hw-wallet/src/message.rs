use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hw_chain::Chain;
use trezor_connect::thp::{SignMessageRequest, SignMessageResponse};

use crate::chain::infer_chain_from_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

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

pub fn build_sign_message_request(
    chain: Chain,
    path: Vec<u32>,
    message: &str,
    is_hex: bool,
    chunkify: bool,
) -> WalletResult<SignMessageRequest> {
    validate_path_for_chain(chain, &path)?;

    let message_bytes = if is_hex {
        decode(message)?
    } else {
        message.as_bytes().to_vec()
    };

    if message_bytes.is_empty() {
        return Err(WalletError::Signing(
            "message must not be empty after encoding".into(),
        ));
    }

    match chain {
        Chain::Bitcoin => {
            Ok(SignMessageRequest::bitcoin(path, message_bytes).with_chunkify(chunkify))
        }
        Chain::Ethereum => {
            Ok(SignMessageRequest::ethereum(path, message_bytes).with_chunkify(chunkify))
        }
        Chain::Solana => Err(WalletError::Signing(
            "message signing is currently unsupported for Solana".into(),
        )),
    }
}

pub fn normalize_message_signature(
    response: &SignMessageResponse,
) -> WalletResult<NormalizedMessageSignature> {
    match response.chain {
        Chain::Bitcoin => Ok(NormalizedMessageSignature {
            encoding: SignatureEncoding::Base64,
            value: BASE64.encode(&response.signature),
        }),
        Chain::Ethereum => Ok(NormalizedMessageSignature {
            encoding: SignatureEncoding::Hex,
            value: format!("0x{}", hex::encode(&response.signature)),
        }),
        Chain::Solana => Err(WalletError::Signing(
            "message signing is currently unsupported for Solana".into(),
        )),
    }
}

fn validate_path_for_chain(chain: Chain, path: &[u32]) -> WalletResult<()> {
    if path.len() < 3 {
        return Err(WalletError::InvalidBip32Path(format!(
            "message-sign path must contain at least 3 segments for {chain:?}"
        )));
    }

    if let Some(inferred) = infer_chain_from_path(path)
        && inferred != chain
    {
        return Err(WalletError::InvalidBip32Path(format!(
            "chain/path mismatch: explicit {chain:?} conflicts with inferred {inferred:?}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_eth_sign_message_request_from_utf8() {
        let request = build_sign_message_request(
            Chain::Ethereum,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            "hello",
            false,
            true,
        )
        .unwrap();
        assert_eq!(request.chain, Chain::Ethereum);
        assert_eq!(request.message, b"hello".to_vec());
        assert!(request.chunkify);
    }

    #[test]
    fn build_btc_sign_message_request_from_hex() {
        let request = build_sign_message_request(
            Chain::Bitcoin,
            vec![0x8000_002c, 0x8000_0000, 0x8000_0000],
            "0x68656c6c6f",
            true,
            false,
        )
        .unwrap();
        assert_eq!(request.chain, Chain::Bitcoin);
        assert_eq!(request.message, b"hello".to_vec());
    }

    #[test]
    fn rejects_empty_message() {
        let err = build_sign_message_request(
            Chain::Ethereum,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            "",
            false,
            false,
        )
        .expect_err("empty message should fail");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_chain_path_mismatch() {
        let err = build_sign_message_request(
            Chain::Ethereum,
            vec![0x8000_002c, 0x8000_0000, 0x8000_0000],
            "hello",
            false,
            false,
        )
        .expect_err("mismatch should fail");
        assert!(err.to_string().contains("chain/path mismatch"));
    }

    #[test]
    fn normalizes_bitcoin_signature_as_base64() {
        let response = SignMessageResponse {
            chain: Chain::Bitcoin,
            address: "bc1qtest".into(),
            signature: vec![0x11, 0x22, 0x33],
        };
        let normalized = normalize_message_signature(&response).unwrap();
        assert_eq!(normalized.encoding, SignatureEncoding::Base64);
        assert_eq!(normalized.value, "ESIz");
    }

    #[test]
    fn normalizes_ethereum_signature_as_hex() {
        let response = SignMessageResponse {
            chain: Chain::Ethereum,
            address: "0x1234".into(),
            signature: vec![0xaa, 0xbb],
        };
        let normalized = normalize_message_signature(&response).unwrap();
        assert_eq!(normalized.encoding, SignatureEncoding::Hex);
        assert_eq!(normalized.value, "0xaabb");
    }
}
