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
pub struct SignMessageBtcArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub message: String,
    #[arg(long, default_value_t = false)]
    pub hex: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl SignMessageBtcArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let path = MessagePath::resolve(Chain::Bitcoin, self.path.as_deref())?;
        let request = SignMessageRequest::from_message(
            Chain::Bitcoin,
            path.indices,
            &self.message,
            self.hex,
            self.chunkify,
            &[],
        )
        .context("failed to build BTC sign-message request")?;

        info!(
            "sign-message command started: chain=bitcoin path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
            path.text,
            self.hex,
            self.chunkify,
            self.connect.timeout_secs,
            self.connect.thp_timeout_secs
        );

        let mut workflow = self
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
}
