use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::ble::{BootstrapTarget, SessionBootstrap, SessionBootstrapOptions, SessionPhase};
use tracing::info;

use crate::device::ConnectArgs;
use crate::pairing::CliPairingController;

#[derive(Args, Debug)]
pub struct PairArgs {
    #[command(flatten)]
    pub connect: ConnectArgs,
    #[arg(long)]
    pub force: bool,
}

impl PairArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        info!(
            "pair command started: scan_timeout_secs={}, thp_timeout_secs={}, force={}",
            self.connect.timeout_secs, self.connect.thp_timeout_secs, self.force
        );

        let storage_path = self.connect.storage_path();
        if self.force && storage_path.exists() {
            std::fs::remove_file(&storage_path).with_context(|| {
                format!(
                    "failed to clear existing pairing storage at {}",
                    storage_path.display()
                )
            })?;
            println!("Cleared saved pairing state: {}", storage_path.display());
        }

        let mut workflow = self
            .connect
            .open_workflow(
                skip_pairing,
                "pair",
                "Remove this Trezor from macOS Bluetooth settings, then re-run `hw-cli pair --force`.",
            )
            .await?;
        info!(
            "pair identity: host_name='{}', app_name='{}'",
            workflow.host_config().host_name,
            workflow.host_config().app_name
        );

        let options = SessionBootstrapOptions {
            try_to_unlock: true,
            ..SessionBootstrapOptions::default()
        };
        println!("Running pair workflow...");
        let mut step = workflow
            .advance_session_bootstrap(false, BootstrapTarget::Paired, &options)
            .await
            .context("failed to establish authenticated pairing state")?;
        if step == SessionPhase::NeedsPairingCode {
            println!(
                "Sending pairing request with host/app labels: '{}' / '{}'.",
                workflow.host_config().host_name,
                workflow.host_config().app_name
            );
            workflow
                .pairing(Some(&CliPairingController))
                .await
                .context("pairing failed")?;
            println!("Pairing complete.");
            info!("pairing interaction flow completed");
            step = workflow
                .advance_session_bootstrap(false, BootstrapTarget::Paired, &options)
                .await
                .context("failed to finalize paired state after code entry")?;
        }

        if step != SessionPhase::NeedsSession {
            bail!("pair workflow ended in unexpected state: {:?}", step);
        }
        println!("Pairing state is ready.");
        println!(
            "Known credentials: {}",
            workflow.host_config().known_credentials.len()
        );
        println!("Saved host state to: {}", storage_path.display());

        Ok(())
    }
}
