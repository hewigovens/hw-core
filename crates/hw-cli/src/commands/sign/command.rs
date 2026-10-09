use anyhow::Result;
use clap::{Args, Subcommand};

use super::btc::SignBtcArgs;
use super::eth::SignEthArgs;
use super::sol::SignSolArgs;

#[derive(Args, Debug)]
pub struct SignArgs {
    #[command(subcommand)]
    pub command: SignCommand,
}

#[derive(Subcommand, Debug)]
pub enum SignCommand {
    Eth(SignEthArgs),
    Btc(SignBtcArgs),
    Sol(SignSolArgs),
}

impl SignArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        match self.command {
            SignCommand::Eth(args) => args.run(skip_pairing).await,
            SignCommand::Btc(args) => args.run(skip_pairing).await,
            SignCommand::Sol(args) => args.run(skip_pairing).await,
        }
    }
}
