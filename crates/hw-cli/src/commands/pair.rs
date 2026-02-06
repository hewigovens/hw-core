use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ble_transport::{BleManager, BleSession};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{FileStorage, HostConfig, Phase, ThpWorkflow};

use crate::cli::{PairArgs, PairingMethod};
use crate::commands::common::{select_device, trezor_profile};
use crate::config::{default_host_name, default_storage_path};
use crate::pairing::CliPairingController;

pub async fn run(args: PairArgs) -> Result<()> {
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
    let manager = BleManager::new().await.context("BLE manager init failed")?;

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, args.timeout_secs
    );
    let devices = manager
        .scan_profile(profile, Duration::from_secs(args.timeout_secs))
        .await
        .context("BLE scan failed")?;

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

    let (info, peripheral) = selected.into_parts();
    let session = BleSession::new(peripheral, profile, info)
        .await
        .context("opening BLE session failed")?;
    let backend = BleBackend::from_session(session);

    let host_name = args.host_name.unwrap_or_else(default_host_name);
    let config = HostConfig::new(host_name, args.app_name);
    let storage = Arc::new(FileStorage::new(storage_path.clone()));
    let mut workflow = ThpWorkflow::with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;

    workflow
        .create_channel()
        .await
        .context("create-channel failed")?;
    workflow
        .handshake(false)
        .await
        .context("handshake failed")?;

    match workflow.state().phase() {
        Phase::Pairing => {
            let controller = CliPairingController;
            workflow
                .pairing(Some(&controller))
                .await
                .context("pairing failed")?;
            println!("Pairing complete.");
        }
        Phase::Paired => {
            println!("Device already paired (or auto-paired).");
        }
        other => {
            bail!("unexpected workflow phase after handshake: {:?}", other);
        }
    }

    println!(
        "Known credentials: {}",
        workflow.host_config().known_credentials.len()
    );
    println!("Saved host state to: {}", storage_path.display());
    Ok(())
}
