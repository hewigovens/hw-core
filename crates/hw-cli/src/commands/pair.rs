use anyhow::{Context, Result, bail};
use hw_wallet::ble::{SessionPhase, advance_to_paired};
use tracing::info;

use crate::cli::{PairArgs, PairingMethod};
use crate::commands::common::{ConnectWorkflowOptions, connect_workflow};
use crate::config::default_storage_path;
use crate::pairing::CliPairingController;

pub async fn run(args: PairArgs, skip_pairing: bool) -> Result<()> {
    info!(
        "pair command started: pairing_method={:?}, scan_timeout_secs={}, thp_timeout_secs={}, force={}",
        args.pairing_method, args.timeout_secs, args.thp_timeout_secs, args.force
    );
    if args.pairing_method != PairingMethod::Ble {
        bail!("only --pairing-method ble is supported");
    }

    let storage_path = args.storage_path.unwrap_or_else(default_storage_path);
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
        ConnectWorkflowOptions {
            scan_timeout_secs: args.timeout_secs,
            thp_timeout_secs: args.thp_timeout_secs,
            device_id: args.device_id.clone(),
            storage_path: Some(storage_path),
            host_name: args.host_name.clone(),
            app_name: args.app_name.clone(),
            skip_pairing,
        },
        "pair",
        "Remove this Trezor from macOS Bluetooth settings, then re-run `hw-cli pair --force`.",
    )
    .await?;
    info!(
        "pair identity: host_name='{}', app_name='{}'",
        workflow.host_config().host_name,
        workflow.host_config().app_name
    );

    let try_to_unlock = true;
    println!("Running pair workflow...");
    let mut step = advance_to_paired(&mut workflow, try_to_unlock)
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
        step = advance_to_paired(&mut workflow, try_to_unlock)
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
