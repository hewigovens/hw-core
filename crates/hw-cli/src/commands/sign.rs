use anyhow::{Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::btc::{
    build_sign_tx_request as build_btc_sign_tx_request, parse_tx_json as parse_btc_tx_json,
};
use hw_wallet::eth::{build_sign_tx_request, parse_tx_json, verify_sign_tx_response};
use hw_wallet::hex::decode as decode_hex;
use tracing::info;
use trezor_connect::thp::{SignTxRequest, ThpBackend, ThpWorkflow};

use crate::cli::{SignArgs, SignBtcArgs, SignCommand, SignEthArgs, SignSolArgs};
use crate::commands::common::{ConnectWorkflowOptions, connect_ready_workflow};

pub async fn run(args: SignArgs) -> Result<()> {
    match args.command {
        SignCommand::Eth(args) => run_eth(args).await,
        SignCommand::Btc(args) => run_btc(args).await,
        SignCommand::Sol(args) => run_sol(args).await,
    }
}

async fn run_eth(args: SignEthArgs) -> Result<()> {
    let path = parse_bip32_path(&args.path)?;
    let tx_json = read_tx_argument(&args.tx)?;

    let tx = parse_tx_json(&tx_json).context("failed to parse tx JSON")?;
    info!(
        "sign command started: chain=ethereum path='{}' to={} chain_id={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path, tx.to, tx.chain_id, args.timeout_secs, args.thp_timeout_secs
    );
    let request = build_sign_tx_request(path, tx).context("failed to build sign request")?;

    let mut workflow = connect_ready_workflow(
        ConnectWorkflowOptions {
            scan_timeout_secs: args.timeout_secs,
            thp_timeout_secs: args.thp_timeout_secs,
            device_id: args.device_id.clone(),
            storage_path: args.storage_path.clone(),
            host_name: args.host_name.clone(),
            app_name: args.app_name.clone(),
        },
        "sign",
        "Remove this Trezor from macOS Bluetooth settings, then pair again.",
    )
    .await?;

    println!("Requesting ETH transaction signature from device...");
    let response = sign_tx_with_workflow(&mut workflow, request.clone()).await?;
    println!("v: {}", response.v);
    println!("r: 0x{}", hex::encode(&response.r));
    println!("s: 0x{}", hex::encode(&response.s));
    if let Ok(verification) = verify_sign_tx_response(&request, &response) {
        println!("tx_hash: 0x{}", hex::encode(verification.tx_hash));
        println!("recovered_address: {}", verification.recovered_address);
    }

    Ok(())
}

async fn run_sol(args: SignSolArgs) -> Result<()> {
    let path = parse_bip32_path(&args.path)?;
    let tx = read_tx_argument(&args.tx)?;
    let serialized_tx = decode_hex(&tx).context("failed to decode Solana tx bytes")?;
    info!(
        "sign command started: chain=solana path='{}' tx_bytes={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path,
        serialized_tx.len(),
        args.timeout_secs,
        args.thp_timeout_secs
    );
    let request = SignTxRequest::solana(path, serialized_tx);

    let mut workflow = connect_ready_workflow(
        ConnectWorkflowOptions {
            scan_timeout_secs: args.timeout_secs,
            thp_timeout_secs: args.thp_timeout_secs,
            device_id: args.device_id.clone(),
            storage_path: args.storage_path.clone(),
            host_name: args.host_name.clone(),
            app_name: args.app_name.clone(),
        },
        "sign",
        "Remove this Trezor from macOS Bluetooth settings, then pair again.",
    )
    .await?;

    println!("Requesting SOL transaction signature from device...");
    let response = sign_tx_with_workflow(&mut workflow, request).await?;
    println!("signature: 0x{}", hex::encode(&response.r));
    Ok(())
}

async fn run_btc(args: SignBtcArgs) -> Result<()> {
    let tx_json = read_tx_argument(&args.tx)?;
    let tx = parse_btc_tx_json(&tx_json).context("failed to parse btc tx JSON")?;
    let request = build_btc_sign_tx_request(tx).context("failed to build BTC sign request")?;
    info!(
        "sign command started: chain=bitcoin scan_timeout_secs={} thp_timeout_secs={}",
        args.timeout_secs, args.thp_timeout_secs
    );

    let mut workflow = connect_ready_workflow(
        ConnectWorkflowOptions {
            scan_timeout_secs: args.timeout_secs,
            thp_timeout_secs: args.thp_timeout_secs,
            device_id: args.device_id.clone(),
            storage_path: args.storage_path.clone(),
            host_name: args.host_name.clone(),
            app_name: args.app_name.clone(),
        },
        "sign",
        "Remove this Trezor from macOS Bluetooth settings, then pair again.",
    )
    .await?;

    println!("Requesting BTC transaction signature from device...");
    let response = sign_tx_with_workflow(&mut workflow, request).await?;
    println!("signature: 0x{}", hex::encode(&response.r));
    Ok(())
}

fn read_tx_argument(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        Ok(std::fs::read_to_string(path).with_context(|| format!("reading tx file: {path}"))?)
    } else {
        Ok(value.to_string())
    }
}

async fn sign_tx_with_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTxRequest,
) -> Result<trezor_connect::thp::SignTxResponse>
where
    B: ThpBackend + Send,
{
    workflow.sign_tx(request).await.context("sign-tx failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::commands::test_support::{
        MockBackend, canned_btc_sign_response, canned_eth_sign_response, canned_sol_sign_response,
        default_test_host_config,
    };
    use hw_wallet::ble::{SessionBootstrapOptions, SessionPhase, advance_session_bootstrap};
    use std::time::Duration;
    use trezor_connect::thp::{Chain as ThpChain, ThpWorkflow};

    const BTC_SIGN_WITH_REF_TXS: &str =
        include_str!("../../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");

    #[tokio::test]
    async fn sign_flow_orchestrates_handshake_confirmation_and_session_retry() {
        let backend = MockBackend::paired_with_session_retry(b"sign-test")
            .with_sign_tx_response(canned_eth_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);
        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_nonce(vec![0])
            .with_gas_limit(vec![0x52, 0x08])
            .with_max_fee_per_gas(vec![1])
            .with_max_priority_fee(vec![1])
            .with_to("0x000000000000000000000000000000000000dead".into())
            .with_value(vec![0]);
        let response = sign_tx_with_workflow(&mut workflow, request).await.unwrap();

        assert_eq!(response.v, 0);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.credential_calls, 1);
        assert_eq!(backend.counters.create_session_calls, 2);
        assert_eq!(backend.counters.sign_tx_calls, 1);
        let request = backend.last_sign_tx_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Ethereum);
        assert_eq!(request.chain_id, 1);
    }

    #[tokio::test]
    async fn sign_sol_flow_uses_solana_chain() {
        let backend = MockBackend::paired_with_session_retry(b"sign-sol-test")
            .with_sign_tx_response(canned_sol_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);

        let request = SignTxRequest::solana(
            vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000],
            vec![0x01, 0x02, 0x03],
        );
        let response = sign_tx_with_workflow(&mut workflow, request).await.unwrap();

        assert_eq!(response.chain, ThpChain::Solana);
        assert_eq!(response.r.len(), 64);
        assert!(response.s.is_empty());
        let backend = workflow.backend_mut();
        let request = backend.last_sign_tx_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Solana);
        assert_eq!(
            request.path,
            vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
        );
        assert_eq!(request.data, vec![0x01, 0x02, 0x03]);
    }

    #[tokio::test]
    async fn sign_btc_flow_uses_bitcoin_chain() {
        let backend = MockBackend::paired_with_session_retry(b"sign-btc-test")
            .with_sign_tx_response(canned_btc_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);

        let tx = parse_btc_tx_json(BTC_SIGN_WITH_REF_TXS).unwrap();
        let request = build_btc_sign_tx_request(tx).unwrap();
        let response = sign_tx_with_workflow(&mut workflow, request).await.unwrap();

        assert_eq!(response.chain, ThpChain::Bitcoin);
        assert_eq!(response.r.len(), 64);
        let backend = workflow.backend_mut();
        let request = backend.last_sign_tx_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Bitcoin);
        assert!(request.btc.is_some());
    }
}
