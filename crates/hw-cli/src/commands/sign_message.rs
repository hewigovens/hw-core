use anyhow::{Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::chain::{
    Chain, DEFAULT_BITCOIN_BIP32_PATH, DEFAULT_ETHEREUM_BIP32_PATH, DEFAULT_SOLANA_BIP32_PATH,
};
use hw_wallet::message::SignMessageRequestExt;
use tracing::info;
use trezor_connect::thp::SignMessageRequest;

use self::eth_request::{EthSignRequest, build_eth_sign_request_from_args};
use crate::cli::{
    SignMessageArgs, SignMessageBtcArgs, SignMessageCommand, SignMessageEthArgs, SignMessageSolArgs,
};
use crate::output::{PrintResponse, print_requesting};

mod eth_request;

pub async fn run(args: SignMessageArgs, skip_pairing: bool) -> Result<()> {
    match args.command {
        SignMessageCommand::Eth(args) => run_eth(args, skip_pairing).await,
        SignMessageCommand::Btc(args) => run_btc(args, skip_pairing).await,
        SignMessageCommand::Sol(args) => run_sol(args, skip_pairing).await,
    }
}

async fn run_eth(args: SignMessageEthArgs, skip_pairing: bool) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_ETHEREUM_BIP32_PATH)
        .to_string();
    let path_indices = parse_bip32_path(&path)?;
    let request = build_eth_sign_request_from_args(&args, path_indices)
        .context("failed to build ETH sign-message request")?;

    let mut workflow = args
        .connect
        .open_ready_workflow(skip_pairing, "sign-message")
        .await?;

    match request {
        EthSignRequest::Message(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip191 path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
                path,
                args.hex,
                args.chunkify,
                args.connect.timeout_secs,
                args.connect.thp_timeout_secs
            );
            print_requesting("ETH message signature");
            let response = workflow
                .sign_message(request)
                .await
                .context("sign-message failed")?;
            response.print()?;
        }
        EthSignRequest::TypedData(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip712 path='{}' scan_timeout_secs={} thp_timeout_secs={}",
                path, args.connect.timeout_secs, args.connect.thp_timeout_secs
            );
            print_requesting("ETH typed-data signature");
            let response = workflow
                .sign_typed_data(request)
                .await
                .context("sign-message failed for --type eip712")?;
            response.print()?;
        }
    }

    Ok(())
}

async fn run_btc(args: SignMessageBtcArgs, skip_pairing: bool) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_BITCOIN_BIP32_PATH)
        .to_string();
    let path_indices = parse_bip32_path(&path)?;
    let request = SignMessageRequest::from_message(
        Chain::Bitcoin,
        path_indices,
        &args.message,
        args.hex,
        args.chunkify,
        &[],
    )
    .context("failed to build BTC sign-message request")?;

    info!(
        "sign-message command started: chain=bitcoin path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
        path, args.hex, args.chunkify, args.connect.timeout_secs, args.connect.thp_timeout_secs
    );

    let mut workflow = args
        .connect
        .open_ready_workflow(skip_pairing, "sign-message")
        .await?;

    print_requesting("BTC message signature");
    let response = workflow
        .sign_message(request)
        .await
        .context("sign-message failed")?;
    response.print()
}

async fn run_sol(args: SignMessageSolArgs, skip_pairing: bool) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_SOLANA_BIP32_PATH)
        .to_string();
    let path_indices = parse_bip32_path(&path)?;
    let request = SignMessageRequest::from_message(
        Chain::Solana,
        path_indices,
        &args.message,
        args.hex,
        args.chunkify,
        &args.signers,
    )
    .context("failed to build SOL sign-message request")?;

    info!(
        "sign-message command started: chain=solana path='{}' hex={} chunkify={} signers={} scan_timeout_secs={} thp_timeout_secs={}",
        path,
        args.hex,
        args.chunkify,
        args.signers.len(),
        args.connect.timeout_secs,
        args.connect.thp_timeout_secs
    );

    let mut workflow = args
        .connect
        .open_ready_workflow(skip_pairing, "sign-message")
        .await?;

    print_requesting("SOL message signature");
    let response = workflow
        .sign_message(request)
        .await
        .context("sign-message failed")?;
    response.print()
}
