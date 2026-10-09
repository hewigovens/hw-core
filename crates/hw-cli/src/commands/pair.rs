use anyhow::{Context, Result, bail};
use hw_wallet::ble::{BootstrapTarget, SessionBootstrap, SessionBootstrapOptions, SessionPhase};
use tracing::info;

use crate::cli::PairArgs;
use crate::commands::common::connect_workflow;
use crate::config::default_storage_path;
use crate::pairing::CliPairingController;

pub async fn run(args: PairArgs, skip_pairing: bool) -> Result<()> {
    info!(
        "pair command started: scan_timeout_secs={}, thp_timeout_secs={}, force={}",
        args.connect.timeout_secs, args.connect.thp_timeout_secs, args.force
    );

    let mut connect = args.connect;
    let storage_path = connect
        .storage_path
        .get_or_insert_with(default_storage_path)
        .clone();
    if args.force && storage_path.exists() {
        std::fs::remove_file(&storage_path).with_context(|| {
            format!(
                "failed to clear existing pairing storage at {}",
                storage_path.display()
            )
        })?;
        println!("Cleared saved pairing state: {}", storage_path.display());
    }

    let (mut workflow, storage_path) = connect_workflow(
        &connect,
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
        let controller = CliPairingController;
        workflow
            .pairing(Some(&controller))
            .await
            .context("pairing failed")?;
        println!("Pairing complete.");
        info!("pairing interaction flow completed");
        step = workflow
            .advance_session_bootstrap(false, BootstrapTarget::Paired, &options)
            .await
            .context("failed to finalize paired state after code entry")?;
    }

    match step {
        SessionPhase::NeedsSession => {
            println!("Pairing state is ready.");
        }
        other => {
            bail!("pair workflow ended in unexpected state: {:?}", other);
        }
    }

    println!(
        "Known credentials: {}",
        workflow.host_config().known_credentials.len()
    );
    println!("Saved host state to: {}", storage_path.display());

    Ok(())
}
