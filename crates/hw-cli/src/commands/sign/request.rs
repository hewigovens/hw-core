use anyhow::{Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::btc::TxInput as BtcTxInput;
use hw_wallet::eth::{build_sign_tx_request, parse_tx_json};
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::sol::build_sign_tx_request as build_sol_sign_tx_request;
use trezor_connect::thp::{BtcSignTx, EthSignTx, SolanaSignTx};

use crate::cli::{SignBtcArgs, SignEthArgs, SignSolArgs};
use crate::commands::common::read_inline_or_file_argument;

pub(super) struct EthSignRequest {
    pub(super) request: EthSignTx,
    pub(super) to: String,
    pub(super) chain_id: u64,
}

pub(super) struct SolSignRequest {
    pub(super) request: SolanaSignTx,
    pub(super) tx_bytes: usize,
}

pub(super) fn build_eth_sign_request_from_args(args: &SignEthArgs) -> Result<EthSignRequest> {
    let path = parse_bip32_path(&args.path)?;
    let tx_json = read_inline_or_file_argument(&args.tx, "tx file")?;
    let tx = parse_tx_json(&tx_json).context("failed to parse tx JSON")?;

    let to = tx.to.clone();
    let chain_id = tx.chain_id;
    let request = build_sign_tx_request(path, tx).context("failed to build sign request")?;

    Ok(EthSignRequest {
        request,
        to,
        chain_id,
    })
}

pub(super) fn build_sol_sign_request_from_args(args: &SignSolArgs) -> Result<SolSignRequest> {
    let path = parse_bip32_path(&args.path)?;
    let tx = read_inline_or_file_argument(&args.tx, "tx file")?;
    let serialized_tx = decode_hex(&tx).context("failed to decode Solana tx bytes")?;
    let tx_bytes = serialized_tx.len();

    let request = build_sol_sign_tx_request(path, serialized_tx)
        .context("failed to build Solana sign request")?;

    Ok(SolSignRequest { request, tx_bytes })
}

pub(super) fn build_btc_sign_request_from_args(args: &SignBtcArgs) -> Result<BtcSignTx> {
    let tx_json = read_inline_or_file_argument(&args.tx, "tx file")?;
    let tx = BtcTxInput::from_json(&tx_json).context("failed to parse btc tx JSON")?;
    BtcSignTx::try_from(tx).context("failed to build BTC sign request")
}
