use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::sol::{SolanaSignTxExt, TxAdditionalInfoInput};
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
    /// Token account infos and encoded token definition, as JSON or @file.
    #[arg(long)]
    pub additional_info: Option<String>,
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
        let request = SolanaSignTx::from_serialized_tx(path, serialized_tx)
            .context("failed to build Solana sign request")?;
        let Some(additional_info) = &self.additional_info else {
            return Ok(request);
        };
        let json = read_inline_or_file_argument(additional_info, "additional info file")?;
        let additional_info = TxAdditionalInfoInput::from_json(&json)
            .context("failed to parse Solana additional info")?;
        Ok(request.with_additional_info(additional_info.into()))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::command::SignCommand;
    use crate::cli::{Cli, Command};

    const V0_TX: &str =
        "8001000103e7f64154f14373a327aa566574e7250d23f68cb1025f3f4fa7fbc23ea0cc7b0f";

    fn sign_sol_args(extra: &[&str]) -> super::SignSolArgs {
        let base = [
            "hw-cli",
            "sign",
            "sol",
            "--path",
            "m/44'/501'/0'/0'",
            "--tx",
            V0_TX,
        ];
        let cli = Cli::parse_from(base.iter().chain(extra));
        let Command::Sign(cmd) = cli.command else {
            panic!("expected sign command");
        };
        let SignCommand::Sol(args) = cmd.command else {
            panic!("expected sign sol command");
        };
        args
    }

    #[test]
    fn sign_sol_attaches_additional_info_only_when_given() {
        let request = sign_sol_args(&[]).request().unwrap();
        assert!(request.additional_info.is_none());

        let request = sign_sol_args(&[
            "--additional-info",
            r#"{"token_accounts_infos": [{"base_address": "a", "token_program": "b", "token_mint": "c", "token_account": "d"}], "encoded_token": "dead"}"#,
        ])
        .request()
        .unwrap();
        assert!(request.additional_info.is_some());
    }
}
