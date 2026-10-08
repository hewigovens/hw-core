use super::{
    get_address_for_workflow, pairing_confirm_connection_for_workflow, pairing_start_for_state,
    pairing_submit_code_for_workflow, request_mapping, sign_message_for_workflow,
    sign_tx_for_workflow, sign_typed_data_for_workflow,
};
use trezor_connect::thp::testing::MockBackend;
use trezor_connect::thp::{Chain, HostConfig, PairingMethod, Phase, ThpWorkflow};

use crate::errors::HWCoreError;
use crate::types::{
    GetAddressRequest, SignMessageRequest, SignTxRequest, SignTypedDataRequest, SignatureEncoding,
};

const BTC_SIGN_WITH_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");

fn default_host_config() -> HostConfig {
    let mut config = HostConfig::new("test-host", "hw-core/ffi");
    config.pairing_methods = vec![PairingMethod::CodeEntry];
    config
}

#[tokio::test]
async fn paired_handshake_requires_connection_confirmation_before_session() {
    let backend = MockBackend::paired_connection_flow();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    assert_eq!(workflow.state().phase(), Phase::Pairing);
    assert!(workflow.state().is_paired());

    let err = workflow
        .create_session(None, false, false)
        .await
        .expect_err("session should fail before confirmation");
    assert!(
        err.to_string().contains("connection confirmation"),
        "unexpected error: {err}"
    );

    let progress = pairing_confirm_connection_for_workflow(&mut workflow)
        .await
        .expect("confirmation succeeds");
    assert_eq!(progress.kind, crate::types::PairingProgressKind::Completed);

    workflow
        .create_session(None, false, false)
        .await
        .expect("session succeeds after confirmation");
}

#[tokio::test]
async fn code_entry_pairing_submit_completes_pairing() {
    let backend = MockBackend::code_entry_flow();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    assert_eq!(workflow.state().phase(), Phase::Pairing);
    assert!(!workflow.state().is_paired());

    let prompt = pairing_start_for_state(workflow.state()).expect("pairing prompt");
    assert!(!prompt.requires_connection_confirmation);
    assert!(prompt.available_methods.contains(&PairingMethod::CodeEntry));

    pairing_submit_code_for_workflow(&mut workflow, "123456".into())
        .await
        .expect("pairing completes");
    assert_eq!(workflow.state().phase(), Phase::Paired);
}

#[tokio::test]
async fn typed_address_and_sign_requests_map_to_workflow_calls() {
    let backend = MockBackend::paired_connection_flow();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    pairing_confirm_connection_for_workflow(&mut workflow)
        .await
        .unwrap();
    workflow.create_session(None, false, false).await.unwrap();

    let address = get_address_for_workflow(
        &mut workflow,
        GetAddressRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            show_on_device: true,
            include_public_key: true,
            chunkify: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        address.address,
        "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE"
    );
    assert_eq!(
        address.mac.as_deref(),
        Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert_eq!(address.public_key.as_deref(), Some("xpub-test"));

    let signed = sign_tx_for_workflow(
        &mut workflow,
        SignTxRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            to: "0x000000000000000000000000000000000000dead".into(),
            value: "0x0".into(),
            nonce: "0x0".into(),
            gas_limit: "0x5208".into(),
            chain_id: 1,
            data: "0x".into(),
            max_fee_per_gas: "0x3b9aca00".into(),
            max_priority_fee: "0x59682f00".into(),
            access_list: Vec::new(),
            chunkify: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(signed.chain, Chain::Ethereum);
    assert_eq!(signed.v, 0);
    assert_eq!(signed.r.len(), 32);
    assert_eq!(signed.s.len(), 32);

    let signed_message = sign_message_for_workflow(
        &mut workflow,
        SignMessageRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            message: "hello from ffi".into(),
            is_hex: false,
            chunkify: true,
            signers: Vec::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(signed_message.chain, Chain::Ethereum);
    assert_eq!(signed_message.signature_encoding, SignatureEncoding::Hex);
    assert!(signed_message.signature_formatted.starts_with("0x"));

    let signed_typed_data = sign_typed_data_for_workflow(
        &mut workflow,
        SignTypedDataRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            domain_separator_hash:
                "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            message_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            ),
            data_json: None,
            metamask_v4_compat: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(signed_typed_data.chain, Chain::Ethereum);
    assert_eq!(signed_typed_data.signature_encoding, SignatureEncoding::Hex);
    assert!(signed_typed_data.signature_formatted.starts_with("0x"));

    let backend = workflow.backend_mut();
    let get_address_request = backend.last_get_address_request.as_ref().unwrap();
    assert_eq!(get_address_request.chain, Chain::Ethereum);
    assert!(get_address_request.show_display);
    assert!(get_address_request.include_public_key);
    assert!(get_address_request.chunkify);

    let Some(trezor_connect::thp::SignTxRequest::Ethereum(sign_request)) =
        &backend.last_sign_tx_request
    else {
        panic!("expected an Ethereum sign request");
    };
    assert_eq!(sign_request.chain_id, 1);
    assert_eq!(
        sign_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    let sign_message_request = backend.last_sign_message_request.as_ref().unwrap();
    assert_eq!(sign_message_request.chain, Chain::Ethereum);
    assert_eq!(
        sign_message_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    assert_eq!(sign_message_request.message, b"hello from ffi".to_vec());
    assert!(sign_message_request.chunkify);
    let sign_typed_data_request = backend.last_sign_typed_data_request.as_ref().unwrap();
    assert_eq!(sign_typed_data_request.chain, Chain::Ethereum);
    assert_eq!(
        sign_typed_data_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    match &sign_typed_data_request.payload {
        trezor_connect::thp::SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            assert_eq!(*domain_separator_hash, vec![0x11; 32]);
            assert_eq!(*message_hash, Some(vec![0x22; 32]));
        }
        other => panic!("expected hash payload, got {other:?}"),
    }

    let signed_sol_message = sign_message_for_workflow(
        &mut workflow,
        SignMessageRequest {
            chain: Chain::Solana,
            path: "m/44'/501'/0'/0'".into(),
            message: "hello from ffi".into(),
            is_hex: false,
            chunkify: false,
            signers: Vec::new(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        signed_sol_message.address,
        "So11111111111111111111111111111111111111112"
    );
    assert_eq!(signed_sol_message.signed_data, Some(vec![0xff; 4]));
}

#[test]
fn get_address_request_maps_solana_chain() {
    let mapped = request_mapping::map_get_address_request(GetAddressRequest {
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
    let mapped = request_mapping::map_sign_tx_request(SignTxRequest {
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
    let trezor_connect::thp::SignTxRequest::Solana(mapped) = mapped else {
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
    let err = request_mapping::map_sign_tx_request(SignTxRequest {
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
    let mapped = request_mapping::map_sign_tx_request(SignTxRequest {
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
    assert!(matches!(
        mapped,
        trezor_connect::thp::SignTxRequest::Bitcoin(_)
    ));
}

#[test]
fn sign_message_request_maps_ethereum_chain() {
    let mapped = request_mapping::map_sign_message_request(SignMessageRequest {
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
    let mapped = request_mapping::map_sign_message_request(SignMessageRequest {
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
    let mapped = request_mapping::map_sign_message_request(SignMessageRequest {
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
    let mapped = request_mapping::map_sign_typed_data_request(SignTypedDataRequest {
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
        trezor_connect::thp::SignTypedDataPayload::Hashes {
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
    let err = request_mapping::map_sign_typed_data_request(SignTypedDataRequest {
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
    let mapped = request_mapping::map_sign_typed_data_request(SignTypedDataRequest {
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
        trezor_connect::thp::SignTypedDataPayload::Hashes { message_hash, .. } => {
            assert_eq!(message_hash, None);
        }
        other => panic!("expected hash payload, got {other:?}"),
    }
}

#[test]
fn sign_typed_data_request_rejects_mixed_json_and_hash_payloads() {
    let err = request_mapping::map_sign_typed_data_request(SignTypedDataRequest {
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
