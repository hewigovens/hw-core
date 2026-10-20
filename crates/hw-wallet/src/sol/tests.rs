use trezor_connect::thp::{SolanaSignTx, SolanaTxAdditionalInfo, SolanaTxTokenAccountInfo};

use super::*;
use crate::hex::decode;
use crate::{WalletError, WalletErrorKind};

const SOL_TX_VERSIONS: &str = include_str!("../../../../tests/data/solana/sol_tx_versions.json");

fn fixture(key: &str) -> Vec<u8> {
    let fixtures: serde_json::Value = serde_json::from_str(SOL_TX_VERSIONS).unwrap();
    decode(fixtures[key].as_str().unwrap()).unwrap()
}

fn sol_path() -> Vec<u32> {
    vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
}

fn with_signatures(count: u8, message: Vec<u8>) -> Vec<u8> {
    let mut tx = vec![count];
    tx.extend(std::iter::repeat_n(0u8, 64 * usize::from(count)));
    tx.extend(message);
    tx
}

fn with_version_byte(version_byte: u8) -> Vec<u8> {
    let mut tx = fixture("v0_message_without_lookup_tables");
    tx[0] = version_byte;
    tx
}

#[test]
fn from_serialized_tx_accepts_legacy_and_v0_envelopes() {
    let cases = [
        ("legacy message", fixture("legacy_message")),
        (
            "serialized legacy tx",
            with_signatures(2, fixture("legacy_message")),
        ),
        (
            "v0 message with lookup tables",
            fixture("v0_message_with_lookup_tables"),
        ),
        (
            "v0 message without lookup tables",
            fixture("v0_message_without_lookup_tables"),
        ),
    ];
    for (name, tx) in cases {
        let request = SolanaSignTx::from_serialized_tx(sol_path(), tx.clone())
            .unwrap_or_else(|err| panic!("{name} should be accepted: {err}"));
        assert_eq!(request.serialized_tx, tx, "{name}");
        assert_eq!(request.path, sol_path(), "{name}");
        assert!(request.additional_info.is_none(), "{name}");
    }
}

#[test]
fn from_serialized_tx_rejects_versioned_envelopes_other_than_v0() {
    let mut serialized_v1_tx = fixture("v1_message");
    serialized_v1_tx.extend([0u8; 64]);
    let cases = [
        ("v1 message", fixture("v1_message"), 1),
        ("serialized v1 tx", serialized_v1_tx, 1),
        ("v2 prefix", with_version_byte(0x82), 2),
        ("highest version prefix", with_version_byte(0xff), 0x7f),
    ];
    for (name, tx, version) in cases {
        let err = SolanaSignTx::from_serialized_tx(sol_path(), tx).unwrap_err();
        assert!(
            matches!(err, WalletError::UnsupportedSolanaTxVersion(actual) if actual == version),
            "{name}: {err}"
        );
        assert_eq!(err.kind(), WalletErrorKind::Validation, "{name}");
    }
}

#[test]
fn from_serialized_tx_rejects_short_payloads() {
    for tx in [Vec::new(), vec![0x81], vec![0x01, 0x02, 0x03]] {
        let len = tx.len();
        let err = SolanaSignTx::from_serialized_tx(sol_path(), tx).unwrap_err();
        assert!(matches!(
            err,
            WalletError::SolanaTxTooShort { len: actual, min: MIN_SERIALIZED_TX_BYTES } if actual == len
        ));
        assert_eq!(err.kind(), WalletErrorKind::Validation);
    }
}

#[test]
fn additional_info_input_maps_token_accounts_and_hex_definition() {
    let token_account_json = r#"{
        "base_address": "base",
        "token_program": "program",
        "token_mint": "mint",
        "token_account": "account"
    }"#;
    let token_account = SolanaTxTokenAccountInfo {
        base_address: "base".into(),
        token_program: "program".into(),
        token_mint: "mint".into(),
        token_account: "account".into(),
    };
    let cases = [
        (
            "empty object",
            "{}".to_string(),
            SolanaTxAdditionalInfo::default(),
        ),
        (
            "token account and definition",
            format!(
                r#"{{"token_accounts_infos": [{token_account_json}], "encoded_token": "0xdead"}}"#
            ),
            SolanaTxAdditionalInfo {
                token_accounts_infos: vec![token_account],
                encoded_token: Some(vec![0xde, 0xad]),
            },
        ),
    ];
    for (name, json, expected) in cases {
        let input = TxAdditionalInfoInput::from_json(&json)
            .unwrap_or_else(|err| panic!("{name} should parse: {err}"));
        let info = SolanaTxAdditionalInfo::try_from(input)
            .unwrap_or_else(|err| panic!("{name} should map: {err}"));
        assert_eq!(info, expected, "{name}");
    }
}

#[test]
fn additional_info_input_rejects_malformed_input() {
    let cases = [
        ("not JSON", "token"),
        (
            "token account missing mint",
            r#"{"token_accounts_infos": [{"base_address": "a", "token_program": "b", "token_account": "d"}]}"#,
        ),
        ("non-hex definition", r#"{"encoded_token": "zz"}"#),
    ];
    for (name, json) in cases {
        let err = TxAdditionalInfoInput::from_json(json)
            .and_then(SolanaTxAdditionalInfo::try_from)
            .unwrap_err();
        assert_eq!(err.kind(), WalletErrorKind::Validation, "{name}");
    }
}
