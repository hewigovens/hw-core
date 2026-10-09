use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::sol::SolanaSignTxExt;
use tracing::info;
use trezor_connect::thp::{SignTxResponse, SolanaSignTx};

use crate::device::ConnectArgs;
use crate::input::read_inline_or_file_argument;
use crate::output::{print_hex_field, print_requesting};

#[derive(Args, Debug)]
pub struct SignSolArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub tx: String,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl SignSolArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let request = self.request()?;
        info!(
            "sign command started: chain=solana path='{}' tx_bytes={} scan_timeout_secs={} thp_timeout_secs={}",
            self.path,
            request.serialized_tx.len(),
            self.connect.timeout_secs,
            self.connect.thp_timeout_secs
        );
        let mut workflow = self
            .connect
            .open_ready_workflow(skip_pairing, "sign")
            .await?;

        print_requesting("SOL transaction signature");
        let response = workflow
            .sign_tx(request.into())
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

    fn request(&self) -> Result<SolanaSignTx> {
        let path = parse_bip32_path(&self.path)?;
        let tx = read_inline_or_file_argument(&self.tx, "tx file")?;
        let serialized_tx = decode_hex(&tx).context("failed to decode Solana tx bytes")?;
        SolanaSignTx::from_serialized_tx(path, serialized_tx)
            .context("failed to build Solana sign request")
    }
}
