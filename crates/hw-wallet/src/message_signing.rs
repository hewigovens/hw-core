use hw_chain::Chain;
use trezor_connect::thp::{SignMessageRequest, SignTypedDataRequest};

use crate::chain::infer_chain_from_path;
use crate::eip712::{build_sign_typed_data_request, build_sign_typed_hash_request};
use crate::error::{WalletError, WalletResult};
use crate::message::build_sign_message_request;

/// Builds a validated ETH EIP-191 message-signing request.
pub fn build_eth_eip191_request(
    path: Vec<u32>,
    message: &str,
    is_hex: bool,
    chunkify: bool,
) -> WalletResult<SignMessageRequest> {
    build_sign_message_request(Chain::Ethereum, path, message, is_hex, chunkify)
}

/// Builds a validated ETH EIP-712 typed-data request from the full JSON payload.
pub fn build_eth_eip712_json_request(
    path: Vec<u32>,
    data_json: &str,
    metamask_v4_compat: bool,
) -> WalletResult<SignTypedDataRequest> {
    build_sign_typed_data_request(path, data_json, metamask_v4_compat)
}

/// Builds a validated ETH EIP-712 typed-data request from pre-hashed inputs.
pub fn build_eth_eip712_hash_request(
    path: Vec<u32>,
    domain_separator_hash: &str,
    message_hash: Option<&str>,
) -> WalletResult<SignTypedDataRequest> {
    build_sign_typed_hash_request(path, domain_separator_hash, message_hash)
}

/// Builds a validated ETH EIP-712 typed-data request from either full JSON or
/// pre-hashed inputs.
pub fn build_eth_eip712_request(
    path: Vec<u32>,
    data_json: Option<&str>,
    domain_separator_hash: Option<&str>,
    message_hash: Option<&str>,
    metamask_v4_compat: bool,
) -> WalletResult<SignTypedDataRequest> {
    match (data_json, domain_separator_hash, message_hash) {
        (Some(_), Some(_), _) | (Some(_), None, Some(_)) => Err(WalletError::Signing(
            "ETH EIP-712 signing must use either `data_json` or hash fields, not both".into(),
        )),
        (Some(data_json), None, None) => {
            build_eth_eip712_json_request(path, data_json, metamask_v4_compat)
        }
        (None, Some(domain_separator_hash), message_hash) => {
            build_eth_eip712_hash_request(path, domain_separator_hash, message_hash)
        }
        (None, None, Some(_)) => Err(WalletError::Signing(
            "ETH EIP-712 hash signing requires `domain_separator_hash`".into(),
        )),
        (None, None, None) => Err(WalletError::Signing(
            "ETH EIP-712 signing requires either `data_json` or `domain_separator_hash`".into(),
        )),
    }
}

pub(crate) fn validate_signing_path_for_chain(
    chain: Chain,
    path: &[u32],
    operation: &str,
) -> WalletResult<()> {
    if path.len() < 3 {
        return Err(WalletError::InvalidBip32Path(format!(
            "{operation} path must contain at least 3 segments for {chain:?}"
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

pub(crate) fn validate_eth_signing_path(path: &[u32], operation: &str) -> WalletResult<()> {
    validate_signing_path_for_chain(Chain::Ethereum, path, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const EIP712_MIXED_JSON_AND_HASHES: &str =
        include_str!("../../../tests/data/ethereum/eip712_invalid_json_and_hashes.json");
    const EIP712_HASH_MODE_MISSING_DOMAIN: &str = include_str!(
        "../../../tests/data/ethereum/eip712_invalid_message_hash_without_domain.json"
    );
    const EIP712_MISSING_DOMAIN_TYPE: &str =
        include_str!("../../../tests/data/ethereum/eip712_invalid_missing_domain_type.json");
    const EIP712_MISSING_PRIMARY_TYPE: &str =
        include_str!("../../../tests/data/ethereum/eip712_invalid_missing_primary_type.json");

    fn default_metamask_v4_compat() -> bool {
        true
    }

    #[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize)]
    struct EthTypedDataFixture {
        #[serde(default)]
        data_json: Option<String>,
        #[serde(default)]
        domain_separator_hash: Option<String>,
        #[serde(default)]
        message_hash: Option<String>,
        #[serde(default = "default_metamask_v4_compat")]
        metamask_v4_compat: bool,
    }

    #[test]
    fn build_eth_eip191_request_accepts_message_mode() {
        let request = build_eth_eip191_request(
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
    fn build_eth_eip712_json_request_accepts_json_mode() {
        let request = build_eth_eip712_json_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            r#"{
                "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Mail": [{ "name": "contents", "type": "string" }]
                },
                "primaryType": "Mail",
                "domain": { "name": "Ether Mail" },
                "message": { "contents": "hello" }
            }"#,
            true,
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Ethereum);
    }

    #[test]
    fn build_eth_eip712_hash_request_accepts_hash_mode() {
        let request = build_eth_eip712_hash_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            Some("0x2222222222222222222222222222222222222222222222222222222222222222"),
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Ethereum);
    }

    #[test]
    fn build_eth_eip712_request_rejects_mixed_payload_fixture() {
        let input: EthTypedDataFixture =
            serde_json::from_str(EIP712_MIXED_JSON_AND_HASHES).unwrap();
        let err = build_eth_eip712_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            input.data_json.as_deref(),
            input.domain_separator_hash.as_deref(),
            input.message_hash.as_deref(),
            input.metamask_v4_compat,
        )
        .expect_err("mixed modes should fail");
        assert!(
            err.to_string()
                .contains("must use either `data_json` or hash fields")
        );
    }

    #[test]
    fn build_eth_eip712_request_rejects_hash_mode_without_domain_fixture() {
        let input: EthTypedDataFixture =
            serde_json::from_str(EIP712_HASH_MODE_MISSING_DOMAIN).unwrap();
        let err = build_eth_eip712_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            input.data_json.as_deref(),
            input.domain_separator_hash.as_deref(),
            input.message_hash.as_deref(),
            input.metamask_v4_compat,
        )
        .expect_err("message_hash without domain should fail");
        assert!(err.to_string().contains("requires `domain_separator_hash`"));
    }

    #[test]
    fn build_eth_eip712_json_request_rejects_fixture_missing_domain_type() {
        let err = build_eth_eip712_json_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            EIP712_MISSING_DOMAIN_TYPE,
            true,
        )
        .expect_err("missing EIP712Domain should fail");
        assert!(err.to_string().contains("must include EIP712Domain"));
    }

    #[test]
    fn build_eth_eip712_json_request_rejects_fixture_missing_primary_type() {
        let err = build_eth_eip712_json_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            EIP712_MISSING_PRIMARY_TYPE,
            true,
        )
        .expect_err("missing primaryType struct should fail");
        assert!(err.to_string().contains("missing primaryType"));
    }
}
