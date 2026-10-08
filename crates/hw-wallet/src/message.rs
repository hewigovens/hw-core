use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hw_chain::Chain;
use std::collections::BTreeSet;

use trezor_connect::thp::types::SOLANA_PUBLIC_KEY_LEN;
use trezor_connect::thp::{SignMessageRequest, SignMessageResponse, decode_solana_public_key};

use crate::error::{WalletError, WalletResult};
use crate::hex::decode;
use crate::message_signing::validate_signing_path_for_chain;

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

/// Firmware's OCMS v1 envelope stores the signer count in one byte.
const MAX_SOLANA_MESSAGE_SIGNERS: usize = 255;

/// `signers` are base58 public keys and apply to Solana only; empty means the signing key alone.
pub fn build_sign_message_request(
    chain: Chain,
    path: Vec<u32>,
    message: &str,
    is_hex: bool,
    chunkify: bool,
    signers: &[String],
) -> WalletResult<SignMessageRequest> {
    validate_signing_path_for_chain(chain, &path, "message-sign")?;

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

    if chain != Chain::Solana && !signers.is_empty() {
        return Err(WalletError::Signing(format!(
            "message signers are only supported for Solana, not {chain:?}"
        )));
    }

    match chain {
        Chain::Bitcoin => {
            Ok(SignMessageRequest::bitcoin(path, message_bytes).with_chunkify(chunkify))
        }
        Chain::Ethereum => {
            Ok(SignMessageRequest::ethereum(path, message_bytes).with_chunkify(chunkify))
        }
        Chain::Solana => {
            let message = String::from_utf8(message_bytes).map_err(|_| {
                WalletError::Signing("Solana message must be valid UTF-8 text".into())
            })?;
            let signers = parse_solana_signers(signers)?;
            Ok(SignMessageRequest::solana(path, message, signers).with_chunkify(chunkify))
        }
    }
}

fn parse_solana_signers(signers: &[String]) -> WalletResult<Vec<[u8; SOLANA_PUBLIC_KEY_LEN]>> {
    if signers.len() > MAX_SOLANA_MESSAGE_SIGNERS {
        return Err(WalletError::Signing(format!(
            "Solana message supports at most {MAX_SOLANA_MESSAGE_SIGNERS} signers, got {}",
            signers.len()
        )));
    }
    let mut seen = BTreeSet::new();
    signers
        .iter()
        .map(|signer| {
            let signer = signer.trim();
            let key = decode_solana_public_key(signer).ok_or_else(|| {
                WalletError::Signing(format!(
                    "invalid Solana signer '{signer}': expected a base58 32-byte public key"
                ))
            })?;
            if !seen.insert(key) {
                return Err(WalletError::Signing(format!(
                    "duplicate Solana signer '{signer}'"
                )));
            }
            Ok(key)
        })
        .collect()
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
        Chain::Solana => Ok(NormalizedMessageSignature {
            encoding: SignatureEncoding::Hex,
            value: hex::encode(&response.signature),
        }),
    }
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
            &[],
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
            &[],
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
            &[],
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
            &[],
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
            signed_data: None,
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
            signed_data: None,
        };
        let normalized = normalize_message_signature(&response).unwrap();
        assert_eq!(normalized.encoding, SignatureEncoding::Hex);
        assert_eq!(normalized.value, "0xaabb");
    }

    const SOL_PATH: [u32; 4] = [0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000];
    // Signers from Suite's solanaSignMessage e2e fixture.
    const SOL_SIGNER_A: &str = "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS";
    const SOL_SIGNER_B: &str = "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q";

    fn build_sol(
        message: &str,
        is_hex: bool,
        signers: &[&str],
    ) -> WalletResult<SignMessageRequest> {
        let signers: Vec<String> = signers.iter().map(|s| s.to_string()).collect();
        build_sign_message_request(
            Chain::Solana,
            SOL_PATH.to_vec(),
            message,
            is_hex,
            true,
            &signers,
        )
    }

    #[test]
    fn build_sol_sign_message_request_keeps_signer_order() {
        let request = build_sol("Hello, Trezor!", false, &[SOL_SIGNER_A, SOL_SIGNER_B]).unwrap();

        assert_eq!(request.chain, Chain::Solana);
        assert_eq!(request.message, b"Hello, Trezor!".to_vec());
        assert!(request.chunkify);
        assert_eq!(
            request
                .solana_signers
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            vec![
                "00d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad",
                "66c2f508c9c555cacc9fb26d88e88dd54e210bb5a8bce5687f60d7e75c4cd07f",
            ]
        );
    }

    #[test]
    fn build_sol_sign_message_request_requires_utf8_text() {
        assert_eq!(
            build_sol("0x68656c6c6f", true, &[]).unwrap().message,
            b"hello".to_vec()
        );
        let err = build_sol("0xfffe", true, &[]).expect_err("non-UTF-8 should fail");
        assert!(err.to_string().contains("valid UTF-8"));
    }

    #[test]
    fn rejects_invalid_message_signers() {
        let too_many: Vec<String> = (0..=MAX_SOLANA_MESSAGE_SIGNERS)
            .map(|i| bs58::encode([i as u8; 32]).into_string())
            .collect();
        let cases = [
            (
                Chain::Solana,
                vec!["not-base58!".to_string()],
                "invalid Solana signer",
            ),
            (
                Chain::Solana,
                vec!["7bWpTW".to_string()],
                "invalid Solana signer",
            ),
            (
                Chain::Solana,
                vec![SOL_SIGNER_A.to_string(), SOL_SIGNER_A.to_string()],
                "duplicate Solana signer",
            ),
            (Chain::Solana, too_many, "at most 255 signers"),
            (
                Chain::Ethereum,
                vec![SOL_SIGNER_A.to_string()],
                "only supported for Solana",
            ),
        ];
        for (chain, signers, expected) in cases {
            let path = match chain {
                Chain::Solana => SOL_PATH.to_vec(),
                Chain::Ethereum | Chain::Bitcoin => vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            };
            let err = build_sign_message_request(chain, path, "hello", false, false, &signers)
                .expect_err("invalid signers should fail");
            assert!(err.to_string().contains(expected), "{err}");
        }
    }

    #[test]
    fn normalizes_solana_signature_as_plain_hex() {
        let response = SignMessageResponse {
            chain: Chain::Solana,
            address: SOL_SIGNER_A.into(),
            signature: vec![0xaa, 0xbb],
            signed_data: None,
        };
        let normalized = normalize_message_signature(&response).unwrap();
        assert_eq!(normalized.encoding, SignatureEncoding::Hex);
        assert_eq!(normalized.value, "aabb");
    }
}
