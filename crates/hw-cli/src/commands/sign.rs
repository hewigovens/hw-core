use anyhow::{Context, Result, bail};
use hw_wallet::eth::VerifiedSignature;
use tracing::info;
use trezor_connect::thp::SignTxResponse;

use self::request::{
    build_btc_sign_request_from_args, build_eth_sign_request_from_args,
    build_sol_sign_request_from_args,
};
use crate::cli::{SignArgs, SignBtcArgs, SignCommand, SignEthArgs, SignSolArgs};
use crate::commands::common::{
    connect_ready_workflow, print_eth_sign_tx_response, print_hex_field, print_requesting,
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
        args.path,
        request.to,
        request.chain_id,
        args.connect.timeout_secs,
        args.connect.thp_timeout_secs
    );
    let mut workflow = connect_ready_workflow(&args.connect, skip_pairing, "sign").await?;

    print_requesting("ETH transaction signature");
    let response = workflow
        .sign_tx(request.request.clone().into())
        .await
        .context("sign-tx failed")?;
    let SignTxResponse::Ethereum(signature) = response else {
        bail!(
            "device returned a {:?} signature for an Ethereum transaction",
            response.chain()
        );
    };
    let verification = VerifiedSignature::recover(&request.request, &signature).ok();
    print_eth_sign_tx_response(&signature, verification.as_ref());

    Ok(())
}

async fn run_sol(args: SignSolArgs, skip_pairing: bool) -> Result<()> {
    let request = build_sol_sign_request_from_args(&args)?;
    info!(
        "sign command started: chain=solana path='{}' tx_bytes={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path, request.tx_bytes, args.connect.timeout_secs, args.connect.thp_timeout_secs
    );
    let mut workflow = connect_ready_workflow(&args.connect, skip_pairing, "sign").await?;

    print_requesting("SOL transaction signature");
    let response = workflow
        .sign_tx(request.request.into())
        .await
        .context("sign-tx failed")?;
    let SignTxResponse::Solana { signature } = response else {
        bail!(
            "device returned a {:?} signature for a Solana transaction",
            response.chain()
        );
    };
    print_hex_field("signature", &signature);
    Ok(())
}

async fn run_btc(args: SignBtcArgs, skip_pairing: bool) -> Result<()> {
    let request = build_btc_sign_request_from_args(&args)?;
    info!(
        "sign command started: chain=bitcoin scan_timeout_secs={} thp_timeout_secs={}",
        args.connect.timeout_secs, args.connect.thp_timeout_secs
    );

    let mut workflow = connect_ready_workflow(&args.connect, skip_pairing, "sign").await?;

    print_requesting("BTC transaction signature");
    let response = workflow
        .sign_tx(request.into())
        .await
        .context("sign-tx failed")?;
    let SignTxResponse::Bitcoin { last_signature, .. } = response else {
        bail!(
            "device returned a {:?} signature for a Bitcoin transaction",
            response.chain()
        );
    };
    print_hex_field("signature", &last_signature);
    Ok(())
}
