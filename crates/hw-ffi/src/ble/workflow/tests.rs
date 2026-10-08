use trezor_connect::thp::testing::MockBackend;
use trezor_connect::thp::{
    Chain, HostConfig, PairingMethod, Phase, SignTxRequest as ThpSignTxRequest,
    SignTypedDataPayload, ThpWorkflow,
};

use super::pairing_flow::PairingFlow;
use super::wallet_requests::WalletRequests;
use crate::types::{
    GetAddressRequest, PairingProgressKind, PairingPrompt, SignMessageRequest, SignTxRequest,
    SignTypedDataRequest, SignatureEncoding,
};

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

    let progress = workflow
        .confirm_paired_connection()
        .await
        .expect("confirmation succeeds");
    assert_eq!(progress.kind, PairingProgressKind::Completed);

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

    let prompt = PairingPrompt::try_from(workflow.state()).expect("pairing prompt");
    assert!(!prompt.requires_connection_confirmation);
    assert!(prompt.available_methods.contains(&PairingMethod::CodeEntry));

    workflow
        .submit_pairing_code("123456".into())
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
    workflow.confirm_paired_connection().await.unwrap();
    workflow.create_session(None, false, false).await.unwrap();

    let address = workflow
        .request_address(GetAddressRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            show_on_device: true,
            include_public_key: true,
            chunkify: true,
        })
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

    let signed = workflow
        .request_tx_signature(SignTxRequest {
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
        })
        .await
        .unwrap();
    assert_eq!(signed.chain, Chain::Ethereum);
    assert_eq!(signed.v, 0);
    assert_eq!(signed.r.len(), 32);
    assert_eq!(signed.s.len(), 32);

    let signed_message = workflow
        .request_message_signature(SignMessageRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            message: "hello from ffi".into(),
            is_hex: false,
            chunkify: true,
            signers: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(signed_message.chain, Chain::Ethereum);
    assert_eq!(signed_message.signature_encoding, SignatureEncoding::Hex);
    assert!(signed_message.signature_formatted.starts_with("0x"));

    let signed_typed_data = workflow
        .request_typed_data_signature(SignTypedDataRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            domain_separator_hash:
                "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            message_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            ),
            data_json: None,
            metamask_v4_compat: true,
        })
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

    let Some(ThpSignTxRequest::Ethereum(sign_request)) = &backend.last_sign_tx_request else {
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
        SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            assert_eq!(*domain_separator_hash, vec![0x11; 32]);
            assert_eq!(*message_hash, Some(vec![0x22; 32]));
        }
        other => panic!("expected hash payload, got {other:?}"),
    }

    let signed_sol_message = workflow
        .request_message_signature(SignMessageRequest {
            chain: Chain::Solana,
            path: "m/44'/501'/0'/0'".into(),
            message: "hello from ffi".into(),
            is_hex: false,
            chunkify: false,
            signers: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(
        signed_sol_message.address,
        "So11111111111111111111111111111111111111112"
    );
    assert_eq!(signed_sol_message.signed_data, Some(vec![0xff; 4]));
}
