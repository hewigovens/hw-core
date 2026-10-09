use anyhow::Result;
use clap::{Args, Subcommand};

use super::btc::SignMessageBtcArgs;
use super::eth::SignMessageEthArgs;
use super::sol::SignMessageSolArgs;

#[derive(Args, Debug)]
pub struct SignMessageArgs {
    #[command(subcommand)]
    pub command: SignMessageCommand,
}

#[derive(Subcommand, Debug)]
pub enum SignMessageCommand {
    Eth(SignMessageEthArgs),
    Btc(SignMessageBtcArgs),
    Sol(SignMessageSolArgs),
}

impl SignMessageArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        match self.command {
            SignMessageCommand::Eth(args) => args.run(skip_pairing).await,
            SignMessageCommand::Btc(args) => args.run(skip_pairing).await,
            SignMessageCommand::Sol(args) => args.run(skip_pairing).await,
        }
    }
}
