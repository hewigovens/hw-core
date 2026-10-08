use hw_wallet::ble::{
    BootstrapTarget, SessionBootstrapOptions, SessionPhase, SessionRetryPolicy,
    advance_session_bootstrap,
};
use hw_wallet::btc::{build_sign_tx_request, parse_tx_json};
use hw_wallet::eip712::build_sign_typed_data_request;
use hw_wallet::message::build_sign_message_request;
use trezor_connect::thp::testing::MockBackend;
use trezor_connect::thp::{
    Chain, EthSignTx, HostConfig, PairingMethod, SignTxRequest, SolanaSignTx, ThpWorkflow,
};

const BTC_SIGN_WITH_REF_TXS: &str =
    include_str!("../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");
const ETH_PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];

async fn ready_workflow() -> ThpWorkflow<MockBackend> {
    let mut config = HostConfig::new("test-host", "hw-core/cli");
    config.pairing_methods = vec![PairingMethod::CodeEntry];
    let backend = MockBackend::paired_connection_flow().with_transient_session_failure();
    let mut workflow = ThpWorkflow::new(backend, config);
    let options = SessionBootstrapOptions {
        try_to_unlock: true,
        retry_policy: SessionRetryPolicy {
            retry_delay_ms: 1,
            ..SessionRetryPolicy::default()
        },
        ..SessionBootstrapOptions::default()
    };
    let phase = advance_session_bootstrap(&mut workflow, false, BootstrapTarget::Session, &options)
        .await
        .unwrap();
    assert_eq!(phase, SessionPhase::Ready);
    workflow
}

#[tokio::test]
async fn bootstrap_confirms_connection_and_retries_session() {
    let mut workflow = ready_workflow().await;
    let backend = workflow.backend_mut();
    assert_eq!(backend.counters.credential_calls, 1);
    assert_eq!(backend.counters.create_session_calls, 2);
    assert_eq!(backend.channel_requests, vec![true]);
}

#[tokio::test]
async fn pair_target_stops_before_session_creation() {
    let mut workflow = ThpWorkflow::new(
        MockBackend::paired_connection_flow(),
        HostConfig::new("test-host", "hw-core/cli"),
    );
    let phase = advance_session_bootstrap(
        &mut workflow,
        false,
        BootstrapTarget::Paired,
        &SessionBootstrapOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(phase, SessionPhase::NeedsSession);
    assert_eq!(workflow.backend_mut().counters.create_session_calls, 0);
}

#[tokio::test]
async fn sign_eth_tx_on_ready_session() {
    let mut workflow = ready_workflow().await;
    let request = EthSignTx::new(ETH_PATH.to_vec(), 1)
        .with_nonce(vec![0])
        .with_gas_limit(vec![0x52, 0x08])
        .with_max_fee_per_gas(vec![1])
        .with_max_priority_fee(vec![1])
        .with_to("0x000000000000000000000000000000000000dead".into())
        .with_value(vec![0]);
    let response = workflow.sign_tx(request.into()).await.unwrap();

    assert_eq!(response.v, 0);
    let backend = workflow.backend_mut();
    assert_eq!(backend.counters.sign_tx_calls, 1);
    let Some(SignTxRequest::Ethereum(request)) = &backend.last_sign_tx_request else {
        panic!("expected an Ethereum sign request");
    };
    assert_eq!(request.chain_id, 1);
}

#[tokio::test]
async fn sign_sol_tx_uses_solana_chain() {
    let mut workflow = ready_workflow().await;
    let path = vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000];
    let request = SolanaSignTx {
        path: path.clone(),
        serialized_tx: vec![0x01, 0x02, 0x03],
    };
    let response = workflow.sign_tx(request.into()).await.unwrap();

    assert_eq!(response.chain, Chain::Solana);
    assert_eq!(response.r.len(), 64);
    assert!(response.s.is_empty());
    let Some(SignTxRequest::Solana(request)) = workflow.backend_mut().last_sign_tx_request.clone()
    else {
        panic!("expected a Solana sign request");
    };
    assert_eq!(request.path, path);
    assert_eq!(request.serialized_tx, vec![0x01, 0x02, 0x03]);
}

#[tokio::test]
async fn sign_btc_tx_uses_bitcoin_chain() {
    let mut workflow = ready_workflow().await;
    let tx = parse_tx_json(BTC_SIGN_WITH_REF_TXS).unwrap();
    let response = workflow
        .sign_tx(build_sign_tx_request(tx).unwrap().into())
        .await
        .unwrap();

    assert_eq!(response.chain, Chain::Bitcoin);
    assert_eq!(response.r.len(), 64);
    assert!(matches!(
        workflow.backend_mut().last_sign_tx_request,
        Some(SignTxRequest::Bitcoin(_))
    ));
}

#[tokio::test]
async fn sign_message_uses_requested_chain() {
    let cases = [
        (Chain::Ethereum, ETH_PATH.to_vec(), "hello", false, true),
        (
            Chain::Bitcoin,
            vec![0x8000_002c, 0x8000_0000, 0x8000_0000],
            "68656c6c6f",
            true,
            false,
        ),
    ];
    for (chain, path, message, is_hex, chunkify) in cases {
        let mut workflow = ready_workflow().await;
        let request =
            build_sign_message_request(chain, path, message, is_hex, chunkify, &[]).unwrap();
        let response = workflow.sign_message(request).await.unwrap();

        assert_eq!(response.chain, chain);
        assert_eq!(response.signature.len(), 65);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.sign_message_calls, 1);
        let request = backend.last_sign_message_request.as_ref().unwrap();
        assert_eq!(request.chain, chain);
        assert_eq!(request.chunkify, chunkify);
    }
}

#[tokio::test]
async fn sign_typed_data_uses_ethereum_chain() {
    let mut workflow = ready_workflow().await;
    let request = build_sign_typed_data_request(
        ETH_PATH.to_vec(),
        r#"{
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
        }"#,
        true,
    )
    .unwrap();
    let response = workflow.sign_typed_data(request).await.unwrap();

    assert_eq!(response.chain, Chain::Ethereum);
    assert_eq!(response.signature.len(), 65);
    let backend = workflow.backend_mut();
    assert_eq!(backend.counters.sign_typed_data_calls, 1);
    let request = backend.last_sign_typed_data_request.as_ref().unwrap();
    assert_eq!(request.chain, Chain::Ethereum);
}
