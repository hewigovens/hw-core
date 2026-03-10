use anyhow::{Context, Result};
use hw_wallet::eth::verify_sign_tx_response;
use tracing::info;
use trezor_connect::thp::{SignTxRequest, ThpBackend, ThpWorkflow};

use self::request::{
    build_btc_sign_request_from_args, build_eth_sign_request_from_args,
    build_sol_sign_request_from_args,
};
use crate::cli::{SignArgs, SignBtcArgs, SignCommand, SignEthArgs, SignSolArgs};
use crate::commands::common::{
    connect_ready_command_workflow, print_eth_sign_tx_response, print_hex_field, print_requesting,
};

mod request;

pub async fn run(args: SignArgs, skip_pairing: bool) -> Result<()> {
    match args.command {
        SignCommand::Eth(args) => run_eth(args, skip_pairing).await,
        SignCommand::Btc(args) => run_btc(args, skip_pairing).await,
        SignCommand::Sol(args) => run_sol(args, skip_pairing).await,
    }
}

async fn run_eth(args: SignEthArgs, skip_pairing: bool) -> Result<()> {
    let request = build_eth_sign_request_from_args(&args)?;
    info!(
        "sign command started: chain=ethereum path='{}' to={} chain_id={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path, request.to, request.chain_id, args.timeout_secs, args.thp_timeout_secs
    );
    let mut workflow = connect_ready_command_workflow(&args, skip_pairing, "sign").await?;

    print_requesting("ETH transaction signature");
    let response = sign_tx_with_workflow(&mut workflow, request.request.clone()).await?;
    let verification = verify_sign_tx_response(&request.request, &response).ok();
    print_eth_sign_tx_response(&response, verification.as_ref());

    Ok(())
}

async fn run_sol(args: SignSolArgs, skip_pairing: bool) -> Result<()> {
    let request = build_sol_sign_request_from_args(&args)?;
    info!(
        "sign command started: chain=solana path='{}' tx_bytes={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path, request.tx_bytes, args.timeout_secs, args.thp_timeout_secs
    );
    let mut workflow = connect_ready_command_workflow(&args, skip_pairing, "sign").await?;

    print_requesting("SOL transaction signature");
    let response = sign_tx_with_workflow(&mut workflow, request.request).await?;
    print_hex_field("signature", &response.r);
    Ok(())
}

async fn run_btc(args: SignBtcArgs, skip_pairing: bool) -> Result<()> {
    let request = build_btc_sign_request_from_args(&args)?;
    info!(
        "sign command started: chain=bitcoin scan_timeout_secs={} thp_timeout_secs={}",
        args.timeout_secs, args.thp_timeout_secs
    );

    let mut workflow = connect_ready_command_workflow(&args, skip_pairing, "sign").await?;

    print_requesting("BTC transaction signature");
    let response = sign_tx_with_workflow(&mut workflow, request).await?;
    print_hex_field("signature", &response.r);
    Ok(())
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
        ready_workflow_with_mock,
    };
    use hw_wallet::btc::{
        build_sign_tx_request as build_btc_sign_tx_request, parse_tx_json as parse_btc_tx_json,
    };
    use trezor_connect::thp::Chain as ThpChain;

    const BTC_SIGN_WITH_REF_TXS: &str =
        include_str!("../../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");

    #[tokio::test]
    async fn sign_flow_orchestrates_handshake_confirmation_and_session_retry() {
        let backend = MockBackend::paired_with_session_retry(b"sign-test")
            .with_sign_tx_response(canned_eth_sign_response());
        let mut workflow = ready_workflow_with_mock(backend).await;
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
        let mut workflow = ready_workflow_with_mock(backend).await;

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
        let mut workflow = ready_workflow_with_mock(backend).await;

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
