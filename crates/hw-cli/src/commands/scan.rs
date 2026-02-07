use std::time::Duration;

use anyhow::{Context, Result};
use ble_transport::BleManager;
use tracing::debug;

use crate::cli::ScanArgs;
use crate::commands::common::{print_discovered_devices, trezor_profile};

pub async fn run(args: ScanArgs) -> Result<()> {
    debug!("scan command: duration_secs={}", args.duration_secs);
    let profile = trezor_profile()?;
    debug!(
        "scan profile: id={}, service_uuid={}",
        profile.id, profile.service_uuid
    );
    let manager = BleManager::new().await.context("BLE manager init failed")?;

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, args.duration_secs
    );
    let devices = manager
        .scan_profile(profile, Duration::from_secs(args.duration_secs))
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
