use trezor_connect::thp::{
    BtcInputScriptType, BtcOutputScriptType, BtcSignTx, Chain,
    GetAddressRequest as ThpGetAddressRequest, SignMessageRequest as ThpSignMessageRequest,
    SignTxRequest as ThpSignTxRequest, SignTypedDataPayload,
    SignTypedDataRequest as ThpSignTypedDataRequest, SolanaTxAdditionalInfo,
    SolanaTxTokenAccountInfo,
};

use crate::errors::HWCoreError;
use crate::types::{
    BitcoinRefTx, BitcoinRefTxInput, BitcoinRefTxOutput, BitcoinSignTxRequest, BitcoinTxInput,
    BitcoinTxOutput, DeviceFeatures, EthereumDefinitions, EthereumDefinitionsSource,
    EthereumDisplayFormatDefinition, GetAddressRequest, SignMessageRequest, SignTxRequest,
    SignTypedDataRequest,
};

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
        encoded_network: None,
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
fn sign_tx_request_maps_solana_chain_with_additional_info() {
    let additional_info = SolanaTxAdditionalInfo {
        token_accounts_infos: vec![SolanaTxTokenAccountInfo {
            base_address: "base".into(),
            token_program: "program".into(),
            token_mint: "mint".into(),
            token_account: "account".into(),
        }],
        encoded_token: Some(vec![0xde, 0xad]),
    };
    for expected in [None, Some(additional_info)] {
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
            eth_definitions: None,
            solana_additional_info: expected.clone(),
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
        assert_eq!(mapped.additional_info, expected);
    }
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
        eth_definitions: None,
        solana_additional_info: None,
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
        eth_definitions: None,
        solana_additional_info: None,
    })
    .expect("bitcoin request should map");
    assert!(matches!(mapped, ThpSignTxRequest::Bitcoin(_)));
}

/// Typed equivalent of `btc_sign_with_ref_txs.json`.
fn typed_bitcoin_request() -> BitcoinSignTxRequest {
    let prev_hash = format!("0x{}", "11".repeat(32));
    BitcoinSignTxRequest {
        inputs: vec![BitcoinTxInput {
            path: "m/84'/0'/0'/0/0".into(),
            prev_hash: prev_hash.clone(),
            prev_index: 0,
            amount: 1000,
            sequence: None,
            script_type: BtcInputScriptType::SpendWitness,
        }],
        outputs: vec![
            BitcoinTxOutput {
                address: Some("bc1qexample0000000000000000000000000000000000".into()),
                path: None,
                amount: 900,
                script_type: None,
                op_return_data: None,
            },
            BitcoinTxOutput {
                address: None,
                path: Some("m/84'/0'/0'/1/0".into()),
                amount: 50,
                script_type: None,
                op_return_data: None,
            },
        ],
        ref_txs: vec![BitcoinRefTx {
            hash: prev_hash,
            version: 2,
            lock_time: 0,
            inputs: vec![BitcoinRefTxInput {
                prev_hash: format!("0x{}", "aa".repeat(32)),
                prev_index: 0,
                script_sig: String::new(),
                sequence: None,
            }],
            bin_outputs: vec![BitcoinRefTxOutput {
                amount: 1000,
                script_pubkey: "001400112233445566778899aabbccddeeff00112233".into(),
            }],
            extra_data: None,
        }],
        version: 2,
        lock_time: 0,
        chunkify: false,
    }
}

#[test]
fn typed_bitcoin_request_maps_with_inferred_script_types_and_defaults() {
    let tx = BtcSignTx::try_from(typed_bitcoin_request()).expect("typed request should map");
    assert_eq!(tx.inputs[0].script_type, BtcInputScriptType::SpendWitness);
    assert_eq!(tx.inputs[0].amount, 1000);
    assert_eq!(tx.inputs[0].sequence, 0xffff_ffff);
    assert_eq!(tx.outputs[0].script_type, BtcOutputScriptType::PayToAddress);
    assert_eq!(tx.outputs[1].script_type, BtcOutputScriptType::PayToWitness);
    assert_eq!(tx.ref_txs.len(), 1);
    assert_eq!(tx.ref_txs[0].bin_outputs[0].amount, 1000);
}

#[test]
fn typed_bitcoin_request_rejects_invalid_shapes_before_signing() {
    let mut request = typed_bitcoin_request();
    request.outputs[0].script_type = Some(BtcOutputScriptType::PayToWitness);
    assert!(matches!(
        BtcSignTx::try_from(request),
        Err(HWCoreError::Validation(_))
    ));

    let mut request = typed_bitcoin_request();
    request.ref_txs.clear();
    assert!(
        BtcSignTx::try_from(request).is_err(),
        "inputs must have their reference transaction"
    );
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
        encoded_network: None,
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
        encoded_network: None,
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
        encoded_network: None,
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
        encoded_network: None,
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
        encoded_network: None,
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
        encoded_network: None,
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
        encoded_network: None,
    })
    .expect_err("mixed typed-data payloads should fail");

    assert!(matches!(err, HWCoreError::Validation(_)));
    assert!(
        err.to_string()
            .contains("must use either `data_json` or hash fields")
    );
}

#[test]
fn ethereum_definitions_are_rejected_when_misplaced_or_malformed() {
    let err = ThpGetAddressRequest::try_from(GetAddressRequest {
        chain: Chain::Bitcoin,
        path: "m/84'/0'/0'/0/0".into(),
        show_on_device: false,
        include_public_key: false,
        chunkify: false,
        encoded_network: Some(vec![1]),
    })
    .expect_err("network definitions are Ethereum only");
    assert!(matches!(err, HWCoreError::Validation(_)));

    let err = ThpSignTxRequest::try_from(SignTxRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        to: "0x000000000000000000000000000000000000dead".into(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x5208".into(),
        chain_id: 1,
        data: "0x".into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
        eth_definitions: Some(EthereumDefinitions {
            display_formats: vec![EthereumDisplayFormatDefinition {
                address: "0xdead".into(),
                func_sig: "0xa9059cbb".into(),
                encoded: vec![1],
            }],
            ..EthereumDefinitions::default()
        }),
        solana_additional_info: None,
    })
    .expect_err("display format address must be 20 bytes");
    assert!(matches!(err, HWCoreError::Validation(_)));
}

#[test]
fn definitions_source_selects_version_and_parses_hex_arguments() {
    let features = DeviceFeatures {
        major_version: 2,
        minor_version: 13,
        ..DeviceFeatures::default()
    };
    let source = EthereumDefinitionsSource::for_firmware(features);
    assert_eq!(source.version(), 2);
    assert_eq!(
        source
            .token_url(1, "0xDAC17F958D2EE523A2206206994597C13D831EC7".into())
            .unwrap(),
        "https://data.trezor.io/firmware/definitions/v2/eth/chain-id/1/token-dac17f958d2ee523a2206206994597c13d831ec7.dat"
    );
    assert!(matches!(
        source.display_format_url(
            1,
            "0xdac17f958d2ee523a2206206994597c13d831ec7".into(),
            "0x01".into()
        ),
        Err(HWCoreError::Validation(_))
    ));
}

#[test]
fn sign_tx_request_rejects_metadata_for_another_chain() {
    let request = |chain, eth_definitions, solana_additional_info| SignTxRequest {
        chain,
        path: String::new(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: String::new(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
        eth_definitions,
        solana_additional_info,
    };
    let eth = || Some(EthereumDefinitions::default());
    let sol = || {
        Some(SolanaTxAdditionalInfo {
            token_accounts_infos: Vec::new(),
            encoded_token: None,
        })
    };
    let cases = [
        (Chain::Ethereum, None, sol(), "solana_additional_info"),
        (Chain::Solana, eth(), None, "eth_definitions"),
        (Chain::Bitcoin, eth(), None, "eth_definitions"),
        (Chain::Bitcoin, None, sol(), "solana_additional_info"),
    ];
    for (chain, eth_definitions, solana_additional_info, field) in cases {
        let err =
            ThpSignTxRequest::try_from(request(chain, eth_definitions, solana_additional_info))
                .expect_err("metadata for another chain must be rejected");
        assert!(
            matches!(&err, HWCoreError::Validation(message) if message.starts_with(field)),
            "{chain:?}: unexpected error {err:?}"
        );
    }
}
