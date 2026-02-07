use std::time::Duration;

use anyhow::{Context, Result};
use ble_transport::BleManager;
use hw_wallet::ble::{scan_profile, trezor_profile};
use tracing::debug;

use crate::cli::ScanArgs;
use crate::commands::common::print_discovered_devices;

pub async fn run(args: ScanArgs) -> Result<()> {
    debug!("scan command: duration_secs={}", args.duration_secs);
    let profile = trezor_profile().context("BLE profile not built into this binary")?;
    debug!(
        "scan profile: id={}, service_uuid={}",
        profile.id, profile.service_uuid
    );
    let manager = BleManager::new().await.context("BLE manager init failed")?;

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, args.duration_secs
    );
    let devices = scan_profile(&manager, profile, Duration::from_secs(args.duration_secs))
        .await
        .context("BLE scan failed")?;
    debug!("scan command: discovered {} device(s)", devices.len());

    if devices.is_empty() {
        println!("No devices found.");
        return Ok(());
    }

    print_discovered_devices(&devices);
    Ok(())
}
