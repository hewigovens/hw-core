//! Example that scans for Trezor Safe 7 devices using the btleplug backend.
//!
//! Run with:
//! `cargo run -p ble-transport --example scan_trezor`

use std::time::Duration;

use anyhow::{anyhow, Result};
use ble_transport::{BleManager, BleProfile};

#[tokio::main]
async fn main() -> Result<()> {
    let profile = BleProfile::trezor_safe7()
        .ok_or_else(|| anyhow!("trezor_safe7 profile not enabled in this build"))?;

    let manager = BleManager::new().await?;
    println!("Scanning for {:?} devices…", profile.name);

    let devices = manager
        .scan_profile(profile, Duration::from_secs(5))
        .await?;

    if devices.is_empty() {
        println!("No devices discovered.");
        return Ok(());
    }

    for device in devices {
        let info = device.info();
        println!("• {}", info.id);
        if let Some(name) = &info.name {
            println!("  name: {name}");
        }
        if let Some(rssi) = info.rssi {
            println!("  RSSI: {rssi} dBm");
        }
        if !info.services.is_empty() {
            println!("  services:");
            for uuid in &info.services {
                println!("    - {uuid}");
            }
        }
    }

    Ok(())
}
