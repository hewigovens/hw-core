use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ble_transport::BleManager;
use hw_wallet::WalletError;
use hw_wallet::ble::{
    SessionPhase, advance_to_paired, backend_from_session, connect_trezor_device,
    scan_profile_until_match, trezor_profile, workflow_with_storage,
};
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{FileStorage, HostConfig, PairingMethod as ThpPairingMethod};

use crate::cli::{PairArgs, PairingMethod};
use crate::commands::common::select_device;
use crate::config::{default_host_name, default_storage_path};
use crate::pairing::CliPairingController;

pub async fn run(args: PairArgs) -> Result<()> {
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

    let profile = trezor_profile()?;
    debug!(
        "pair profile: id={}, service_uuid={}",
        profile.id, profile.service_uuid
    );
    let manager = BleManager::new().await.context("BLE manager init failed")?;

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, args.timeout_secs
    );
    let devices = scan_profile_until_match(
        &manager,
        profile,
        Duration::from_secs(args.timeout_secs),
        args.device_id.as_deref(),
    )
    .await
    .context("BLE scan failed")?;
    info!("scan complete: discovered {} device(s)", devices.len());

    if devices.is_empty() {
        bail!("no devices found");
    }

    let selected = select_device(devices, args.device_id.as_deref())?;
    let selected_name = selected
        .info()
        .name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());
    println!(
        "Connecting to {} ({})...",
        selected.info().id,
        selected_name
    );

    println!("Opening BLE session...");
    let session = match timeout(
        Duration::from_secs(args.thp_timeout_secs),
        connect_trezor_device(selected, profile),
    )
    .await
    {
        Err(_) => bail!(
            "opening BLE session timed out after {}s",
            args.thp_timeout_secs
        ),
        Ok(Ok(session)) => session,
        Ok(Err(WalletError::PeerRemovedPairingInfo)) => {
            bail!(
                "opening BLE session failed: peer removed pairing information. Remove this Trezor from macOS Bluetooth settings, then re-run `hw-cli pair --force`."
            );
        }
        Ok(Err(err)) => return Err(err).context("opening BLE session failed"),
    };
    println!("BLE session established.");
    debug!("BLE session established");
    let backend = backend_from_session(session, Duration::from_secs(args.thp_timeout_secs));
    debug!(
        "configured THP backend response timeout: {:?}",
        backend.handshake_timeout()
    );

    let host_name = args.host_name.unwrap_or_else(default_host_name);
    info!(
        "pair identity: host_name='{}', app_name='{}'",
        host_name, args.app_name
    );
    let mut config = HostConfig::new(host_name, args.app_name);
    // Match Suite default to avoid implicit SkipPairing unless explicitly requested later.
    config.pairing_methods = vec![ThpPairingMethod::CodeEntry];
    let storage = Arc::new(FileStorage::new(storage_path.clone()));
    let mut workflow = workflow_with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;
    debug!("workflow initialized with persisted host state");

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
