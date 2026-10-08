use hw_chain::Chain;
use serde::Deserialize;
use trezor_connect::thp::{
    SignMessageRequest, SignMessageResponse, SignTypedDataPayload, SignTypedDataRequest,
    SignTypedDataResponse,
};

use super::sign_message::MAX_SOLANA_MESSAGE_SIGNERS;
use super::*;
use crate::error::WalletResult;

const ETH_PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
const SOL_PATH: [u32; 4] = [0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000];
// Signers from Suite's solanaSignMessage e2e fixture.
const SOL_SIGNER_A: &str = "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS";
const SOL_SIGNER_B: &str = "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q";

const EIP712_MIXED_JSON_AND_HASHES: &str =
    include_str!("../../../../tests/data/ethereum/eip712_invalid_json_and_hashes.json");
const EIP712_HASH_MODE_MISSING_DOMAIN: &str =
    include_str!("../../../../tests/data/ethereum/eip712_invalid_message_hash_without_domain.json");
const EIP712_MISSING_DOMAIN_TYPE: &str =
    include_str!("../../../../tests/data/ethereum/eip712_invalid_missing_domain_type.json");
const EIP712_MISSING_PRIMARY_TYPE: &str =
    include_str!("../../../../tests/data/ethereum/eip712_invalid_missing_primary_type.json");
const MAIL_TYPED_DATA: &str = r#"{
    "types": {
        "EIP712Domain": [{ "name": "name", "type": "string" }],
        "Mail": [
            { "name": "from", "type": "address" },
            { "name": "contents", "type": "string" }
        ]
    },
    "primaryType": "Mail",
    "domain": { "name": "Ether Mail" },
    "message": { "from": "0x1111111111111111111111111111111111111111", "contents": "hello" }
}"#;

#[derive(Debug, Default, Deserialize)]
struct EthTypedDataFixture {
    #[serde(default)]
    data_json: Option<String>,
    #[serde(default)]
    domain_separator_hash: Option<String>,
    #[serde(default)]
    message_hash: Option<String>,
}

#[test]
fn build_eth_sign_message_request_from_utf8() {
    let request = SignMessageRequest::from_message(
        Chain::Ethereum,
        ETH_PATH.to_vec(),
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
    let request = SignMessageRequest::from_message(
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
fn sign_message_rejects_empty_message_and_chain_path_mismatch() {
    for (path, message, expected) in [
        (
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            "",
            "must not be empty",
        ),
        (
            vec![0x8000_002c, 0x8000_0000, 0x8000_0000],
            "hello",
            "chain/path mismatch",
        ),
    ] {
        let err =
            SignMessageRequest::from_message(Chain::Ethereum, path, message, false, false, &[])
                .expect_err("invalid request should fail");
        assert!(err.to_string().contains(expected), "{err}");
    }
}

fn build_sol(message: &str, is_hex: bool, signers: &[&str]) -> WalletResult<SignMessageRequest> {
    let signers: Vec<String> = signers.iter().map(|s| s.to_string()).collect();
    SignMessageRequest::from_message(
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
        let err = SignMessageRequest::from_message(chain, path, "hello", false, false, &signers)
            .expect_err("invalid signers should fail");
        assert!(err.to_string().contains(expected), "{err}");
    }
}

#[test]
fn normalizes_message_signature_per_chain() {
    for (chain, encoding, value) in [
        (Chain::Bitcoin, SignatureEncoding::Base64, "qrs="),
        (Chain::Ethereum, SignatureEncoding::Hex, "0xaabb"),
        (Chain::Solana, SignatureEncoding::Hex, "aabb"),
    ] {
        let response = SignMessageResponse {
            chain,
            address: String::new(),
            signature: vec![0xaa, 0xbb],
            signed_data: None,
        };
        assert_eq!(
            NormalizedMessageSignature::from(&response),
            NormalizedMessageSignature {
                encoding,
                value: value.to_string(),
            },
            "{chain:?}"
        );
    }
}

#[test]
fn typed_hash_request_accepts_valid_hashes_and_domain_only() {
    for (message_hash, expected_message_hash) in [
        (
            Some("0x2222222222222222222222222222222222222222222222222222222222222222"),
            Some(vec![0x22; 32]),
        ),
        (None, None),
    ] {
        let request = SignTypedDataRequest::from_eip712_hashes(
            ETH_PATH.to_vec(),
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            message_hash,
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Ethereum);
        let SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } = request.payload
        else {
            panic!("expected hash payload");
        };
        assert_eq!(domain_separator_hash, vec![0x11; 32]);
        assert_eq!(message_hash, expected_message_hash);
    }
}

#[test]
fn typed_json_request_accepts_full_json() {
    let request =
        SignTypedDataRequest::from_eip712_json(ETH_PATH.to_vec(), MAIL_TYPED_DATA, true).unwrap();

    let SignTypedDataPayload::TypedData(typed) = request.payload else {
        panic!("expected typed-data payload");
    };
    assert_eq!(typed.primary_type, "Mail");
    assert!(typed.metamask_v4_compat);
    assert!(typed.types.contains_key("EIP712Domain"));
    assert!(typed.types.contains_key("Mail"));
}

#[test]
fn eip712_request_rejects_invalid_inputs() {
    let fixture = |json: &str| serde_json::from_str::<EthTypedDataFixture>(json).unwrap();
    let raw_json = |json: &str| EthTypedDataFixture {
        data_json: Some(json.to_string()),
        ..EthTypedDataFixture::default()
    };
    let hashes = |domain: &str| EthTypedDataFixture {
        domain_separator_hash: Some(domain.to_string()),
        ..EthTypedDataFixture::default()
    };
    for (input, expected) in [
        (
            fixture(EIP712_MIXED_JSON_AND_HASHES),
            "must use either `data_json` or hash fields",
        ),
        (
            fixture(EIP712_HASH_MODE_MISSING_DOMAIN),
            "requires `domain_separator_hash`",
        ),
        (
            raw_json(EIP712_MISSING_DOMAIN_TYPE),
            "must include EIP712Domain",
        ),
        (raw_json(EIP712_MISSING_PRIMARY_TYPE), "missing primaryType"),
        (hashes("0x1234"), "domain_separator_hash must be 32 bytes"),
    ] {
        let err = SignTypedDataRequest::from_eip712(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            input.data_json.as_deref(),
            input.domain_separator_hash.as_deref(),
            input.message_hash.as_deref(),
            true,
        )
        .expect_err("invalid input should fail");
        assert!(err.to_string().contains(expected), "{expected}: {err}");
    }
}

#[test]
fn typed_data_signature_is_0x_hex() {
    let response = SignTypedDataResponse {
        chain: Chain::Ethereum,
        address: "0x1234".to_string(),
        signature: vec![0xaa, 0xbb],
    };
    assert_eq!(response.formatted_signature().unwrap(), "0xaabb");
}
