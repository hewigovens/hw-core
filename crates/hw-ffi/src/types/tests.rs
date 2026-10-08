use trezor_connect::thp::{
    Chain, GetAddressRequest as ThpGetAddressRequest, SignMessageRequest as ThpSignMessageRequest,
    SignTxRequest as ThpSignTxRequest, SignTypedDataPayload,
    SignTypedDataRequest as ThpSignTypedDataRequest,
};

use crate::errors::HWCoreError;
use crate::types::{GetAddressRequest, SignMessageRequest, SignTxRequest, SignTypedDataRequest};

const BTC_SIGN_WITH_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");

#[test]
fn get_address_request_maps_solana_chain() {
    let mapped = ThpGetAddressRequest::try_from(GetAddressRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        show_on_device: false,
        include_public_key: true,
        chunkify: true,
    })
    .expect("map request");
    assert_eq!(mapped.chain, Chain::Solana);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
    );
    assert!(!mapped.show_display);
    assert!(mapped.include_public_key);
    assert!(mapped.chunkify);
}

#[test]
fn sign_tx_request_maps_solana_chain() {
    let mapped = ThpSignTxRequest::try_from(SignTxRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: "0x0102030405060708090a0b0c0d0e0f10".into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect("solana request should map");
    let ThpSignTxRequest::Solana(mapped) = mapped else {
        panic!("expected a Solana sign request");
    };
    assert_eq!(
        mapped.serialized_tx,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]
    );
}

#[test]
fn sign_tx_request_rejects_too_short_solana_payload() {
    let err = ThpSignTxRequest::try_from(SignTxRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: "0x010203".into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect_err("short Solana payload should fail");
    assert!(matches!(err, HWCoreError::Validation(_)));
}

#[test]
fn sign_tx_request_maps_bitcoin_chain() {
    let mapped = ThpSignTxRequest::try_from(SignTxRequest {
        chain: Chain::Bitcoin,
        path: String::new(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: BTC_SIGN_WITH_REF_TXS.into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect("bitcoin request should map");
    assert!(matches!(mapped, ThpSignTxRequest::Bitcoin(_)));
}

#[test]
fn sign_message_request_maps_ethereum_chain() {
    let mapped = ThpSignMessageRequest::try_from(SignMessageRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        message: "hello".into(),
        is_hex: false,
        chunkify: true,
        signers: Vec::new(),
    })
    .expect("message request should map");
    assert_eq!(mapped.chain, Chain::Ethereum);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    assert_eq!(mapped.message, b"hello".to_vec());
    assert!(mapped.chunkify);
}

#[test]
fn sign_message_request_maps_bitcoin_hex_payload() {
    let mapped = ThpSignMessageRequest::try_from(SignMessageRequest {
        chain: Chain::Bitcoin,
        path: "m/84'/0'/0'/0/0".into(),
        message: "0x68656c6c6f".into(),
        is_hex: true,
        chunkify: false,
        signers: Vec::new(),
    })
    .expect("message request should map");
    assert_eq!(mapped.chain, Chain::Bitcoin);
    assert_eq!(mapped.message, b"hello".to_vec());
}

#[test]
fn sign_message_request_maps_solana_signers() {
    let mapped = ThpSignMessageRequest::try_from(SignMessageRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        message: "hello".into(),
        is_hex: false,
        chunkify: false,
        signers: vec![
            "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS".into(),
            "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q".into(),
        ],
    })
    .expect("solana message request should map");
    assert_eq!(mapped.chain, Chain::Solana);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
    );
    assert_eq!(mapped.solana_signers.len(), 2);
    assert_eq!(mapped.solana_signers[0][..2], [0x00, 0xd1]);
}

#[test]
fn sign_typed_data_request_maps_ethereum_hashes() {
    let mapped = ThpSignTypedDataRequest::try_from(SignTypedDataRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        domain_separator_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        message_hash: Some(
            "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
        ),
        data_json: None,
        metamask_v4_compat: true,
    })
    .expect("typed-data request should map");
    assert_eq!(mapped.chain, Chain::Ethereum);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    match mapped.payload {
        SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            assert_eq!(domain_separator_hash, vec![0x11; 32]);
            assert_eq!(message_hash, Some(vec![0x22; 32]));
        }
        other => panic!("expected hash payload, got {other:?}"),
    }
}

#[test]
fn sign_typed_data_request_rejects_message_hash_without_domain() {
    let err = ThpSignTypedDataRequest::try_from(SignTypedDataRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        domain_separator_hash: "   ".into(),
        message_hash: Some(
            "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
        ),
        data_json: None,
        metamask_v4_compat: true,
    })
    .expect_err("message hash without domain should fail");

    assert!(matches!(err, HWCoreError::Validation(_)));
    assert!(err.to_string().contains("requires `domain_separator_hash`"));
}

#[test]
fn sign_typed_data_request_treats_whitespace_message_hash_as_absent() {
    let mapped = ThpSignTypedDataRequest::try_from(SignTypedDataRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        domain_separator_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        message_hash: Some("   ".into()),
        data_json: None,
        metamask_v4_compat: true,
    })
    .expect("whitespace message hash should be ignored");

    match mapped.payload {
        SignTypedDataPayload::Hashes { message_hash, .. } => {
            assert_eq!(message_hash, None);
        }
        other => panic!("expected hash payload, got {other:?}"),
    }
}

#[test]
fn sign_typed_data_request_rejects_mixed_json_and_hash_payloads() {
    let err = ThpSignTypedDataRequest::try_from(SignTypedDataRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        domain_separator_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        message_hash: None,
        data_json: Some(
            r#"{
                "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Mail": [{ "name": "contents", "type": "string" }]
                },
                "primaryType": "Mail",
                "domain": { "name": "Ether Mail" },
                "message": { "contents": "hello" }
            }"#
            .into(),
        ),
        metamask_v4_compat: true,
    })
    .expect_err("mixed typed-data payloads should fail");

    assert!(matches!(err, HWCoreError::Validation(_)));
    assert!(
        err.to_string()
            .contains("must use either `data_json` or hash fields")
    );
}
