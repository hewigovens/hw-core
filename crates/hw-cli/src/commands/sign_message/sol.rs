use anyhow::{Context, Result};
use clap::Args;
use hw_wallet::chain::Chain;
use hw_wallet::message::SignMessageRequestExt;
use tracing::info;
use trezor_connect::thp::SignMessageRequest;

use super::message_path::MessagePath;
use crate::device::ConnectArgs;
use crate::output::{PrintResponse, print_requesting};

#[derive(Args, Debug)]
pub struct SignMessageSolArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub message: String,
    #[arg(long, default_value_t = false)]
    pub hex: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    /// Base58 OCMS v1 signer; repeat for multi-signer messages (defaults to the signing key).
    #[arg(long = "signer", value_name = "BASE58")]
    pub signers: Vec<String>,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl SignMessageSolArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let path = MessagePath::resolve(Chain::Solana, self.path.as_deref())?;
        let request = SignMessageRequest::from_message(
            Chain::Solana,
            path.indices,
            &self.message,
            self.hex,
            self.chunkify,
            &self.signers,
        )
        .context("failed to build SOL sign-message request")?;

        info!(
            "sign-message command started: chain=solana path='{}' hex={} chunkify={} signers={} scan_timeout_secs={} thp_timeout_secs={}",
            path.text,
            self.hex,
            self.chunkify,
            self.signers.len(),
            self.connect.timeout_secs,
            self.connect.thp_timeout_secs
        );

        let mut workflow = self
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
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::command::SignMessageCommand;
    use crate::cli::{Cli, Command};

    #[test]
    fn sign_message_sol_collects_repeated_signers() {
        let cli = Cli::parse_from([
            "hw-cli",
            "sign-message",
            "sol",
            "--message",
            "hello",
            "--signer",
            "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS",
            "--signer",
            "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q",
        ]);
        let Command::SignMessage(cmd) = cli.command else {
            panic!("expected sign-message command");
        };
        let SignMessageCommand::Sol(args) = cmd.command else {
            panic!("expected sign-message sol command");
        };

        assert_eq!(
            args.signers,
            [
                "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS",
                "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q",
            ]
        );
    }
}
