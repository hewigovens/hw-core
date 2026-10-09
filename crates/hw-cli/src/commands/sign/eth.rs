use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::eth::{TxInput, VerifiedSignature};
use tracing::info;
use trezor_connect::thp::{EthSignTx, SignTxResponse};

use crate::device::ConnectArgs;
use crate::input::read_inline_or_file_argument;
use crate::output::{PrintResponse, print_hex_field, print_labeled_value, print_requesting};

#[derive(Args, Debug)]
pub struct SignEthArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub tx: String,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl SignEthArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let request = self.request()?;
        info!(
            "sign command started: chain=ethereum path='{}' to={} chain_id={} scan_timeout_secs={} thp_timeout_secs={}",
            self.path,
            request.to,
            request.chain_id,
            self.connect.timeout_secs,
            self.connect.thp_timeout_secs
        );
        let mut workflow = self
            .connect
            .open_ready_workflow(skip_pairing, "sign")
            .await?;

        print_requesting("ETH transaction signature");
        let response = workflow
            .sign_tx(request.clone().into())
            .await
            .context("sign-tx failed")?;
        let SignTxResponse::Ethereum(signature) = response else {
            bail!(
                "device returned a {:?} signature for an Ethereum transaction",
                response.chain()
            );
        };
        signature.print()?;
        if let Ok(verification) = VerifiedSignature::recover(&request, &signature) {
            print_hex_field("tx_hash", &verification.tx_hash);
            print_labeled_value("recovered_address", &verification.recovered_address);
        }

        Ok(())
    }

    fn request(&self) -> Result<EthSignTx> {
        let path = parse_bip32_path(&self.path)?;
        let tx_json = read_inline_or_file_argument(&self.tx, "tx file")?;
        TxInput::from_json(&tx_json)
            .context("failed to parse tx JSON")?
            .into_sign_tx(path)
            .context("failed to build sign request")
    }
}
