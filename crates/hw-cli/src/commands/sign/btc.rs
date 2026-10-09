use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::btc::TxInput;
use tracing::info;
use trezor_connect::thp::{BtcSignTx, SignTxResponse};

use crate::device::ConnectArgs;
use crate::input::read_inline_or_file_argument;
use crate::output::{print_hex_field, print_requesting};

#[derive(Args, Debug)]
pub struct SignBtcArgs {
    #[arg(long)]
    pub tx: String,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl SignBtcArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let request = self.request()?;
        info!(
            "sign command started: chain=bitcoin scan_timeout_secs={} thp_timeout_secs={}",
            self.connect.timeout_secs, self.connect.thp_timeout_secs
        );
        let mut workflow = self
            .connect
            .open_ready_workflow(skip_pairing, "sign")
            .await?;

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

    fn request(&self) -> Result<BtcSignTx> {
        let tx_json = read_inline_or_file_argument(&self.tx, "tx file")?;
        let tx = TxInput::from_json(&tx_json).context("failed to parse btc tx JSON")?;
        BtcSignTx::try_from(tx).context("failed to build BTC sign request")
    }
}
