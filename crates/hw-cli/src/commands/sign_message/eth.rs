use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Args, ValueEnum};
use hw_wallet::chain::Chain;
use hw_wallet::message::{SignMessageRequestExt, SignTypedDataRequestExt};
use tracing::info;
use trezor_connect::thp::{SignMessageRequest, SignTypedDataRequest};

use super::message_path::MessagePath;
use crate::device::ConnectArgs;
use crate::input::read_text_file;
use crate::output::{PrintResponse, print_requesting};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EthSignMessageType {
    Eip191,
    Eip712,
}

#[derive(Args, Debug)]
pub struct SignMessageEthArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub message: Option<String>,
    #[arg(long = "type", value_enum, default_value_t = EthSignMessageType::Eip191)]
    pub message_type: EthSignMessageType,
    #[arg(long, default_value_t = false)]
    pub hex: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    #[arg(long = "data-file")]
    pub data_file: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub metamask_v4_compat: bool,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

#[derive(Debug)]
enum EthMessageRequest {
    Message(SignMessageRequest),
    TypedData(SignTypedDataRequest),
}

impl SignMessageEthArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let path = MessagePath::resolve(Chain::Ethereum, self.path.as_deref())?;
        let request = self
            .request(path.indices)
            .context("failed to build ETH sign-message request")?;

        let mut workflow = self
            .connect
            .open_ready_workflow(skip_pairing, "sign-message")
            .await?;

        match request {
            EthMessageRequest::Message(request) => {
                info!(
                    "sign-message command started: chain=ethereum type=eip191 path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
                    path.text,
                    self.hex,
                    self.chunkify,
                    self.connect.timeout_secs,
                    self.connect.thp_timeout_secs
                );
                print_requesting("ETH message signature");
                workflow
                    .sign_message(request)
                    .await
                    .context("sign-message failed")?
                    .print()
            }
            EthMessageRequest::TypedData(request) => {
                info!(
                    "sign-message command started: chain=ethereum type=eip712 path='{}' scan_timeout_secs={} thp_timeout_secs={}",
                    path.text, self.connect.timeout_secs, self.connect.thp_timeout_secs
                );
                print_requesting("ETH typed-data signature");
                workflow
                    .sign_typed_data(request)
                    .await
                    .context("sign-message failed for --type eip712")?
                    .print()
            }
        }
    }

    fn request(&self, path: Vec<u32>) -> Result<EthMessageRequest> {
        match self.message_type {
            EthSignMessageType::Eip191 => {
                if self.data_file.is_some() {
                    bail!("ETH EIP-191 signing cannot be combined with EIP-712 fields");
                }
                let message = self
                    .message
                    .as_deref()
                    .ok_or_else(|| anyhow!("ETH EIP-191 signing requires `message`"))?;
                let request = SignMessageRequest::from_message(
                    Chain::Ethereum,
                    path,
                    message,
                    self.hex,
                    self.chunkify,
                    &[],
                )?;
                Ok(EthMessageRequest::Message(request))
            }
            EthSignMessageType::Eip712 => {
                if self.message.is_some() {
                    bail!("ETH EIP-712 signing cannot be combined with `message`");
                }
                if self.hex || self.chunkify {
                    bail!("`hex` and `chunkify` are only valid for ETH EIP-191 signing");
                }
                let data_file = self
                    .data_file
                    .as_deref()
                    .ok_or_else(|| anyhow!("--data-file is required for --type eip712"))?;
                let data_json = read_text_file(data_file, "typed-data file")?;
                let request = SignTypedDataRequest::from_eip712_json(
                    path,
                    &data_json,
                    self.metamask_v4_compat,
                )?;
                Ok(EthMessageRequest::TypedData(request))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::command::SignMessageCommand;
    use crate::cli::{Cli, Command};

    #[test]
    fn eth_message_request_rejects_conflicting_or_missing_inputs() {
        for (args, expected) in [
            (
                &[
                    "--type",
                    "eip712",
                    "--message",
                    "hello",
                    "--data-file",
                    "/x",
                ][..],
                "cannot be combined with `message`",
            ),
            (
                &["--type", "eip712"],
                "--data-file is required for --type eip712",
            ),
            (
                &["--type", "eip712", "--data-file", "/x", "--hex"],
                "only valid for ETH EIP-191",
            ),
            (
                &["--message", "hello", "--data-file", "/x"],
                "cannot be combined with EIP-712 fields",
            ),
            (&[], "ETH EIP-191 signing requires `message`"),
        ] {
            let argv = ["hw-cli", "sign-message", "eth"]
                .into_iter()
                .chain(args.iter().copied());
            let Command::SignMessage(cmd) = Cli::parse_from(argv).command else {
                panic!("expected sign-message command");
            };
            let SignMessageCommand::Eth(eth) = cmd.command else {
                panic!("expected sign-message eth command");
            };
            let err = eth
                .request(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0])
                .unwrap_err();
            assert!(err.to_string().contains(expected), "{args:?}: {err}");
        }
    }
}
