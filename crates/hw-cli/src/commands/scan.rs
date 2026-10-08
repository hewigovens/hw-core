use std::time::Duration;

use anyhow::{Context, Result};
use ble_transport::{BleManager, BleProfile};
use clap::Args;
use tracing::debug;

use crate::device::DeviceList;

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(long, default_value_t = 60)]
    pub duration_secs: u64,
}

impl ScanArgs {
    pub async fn run(self) -> Result<()> {
        debug!("scan command: duration_secs={}", self.duration_secs);
        let profile = BleProfile::TREZOR_SAFE7;
        debug!(
            "scan profile: id={}, service_uuid={}",
            profile.id, profile.service_uuid
        );
        let manager = BleManager::new().await.context("BLE manager init failed")?;

        println!(
            "Scanning for {} devices for {}s...",
            profile.name, self.duration_secs
        );
        let devices = manager
            .scan_profile(profile, Duration::from_secs(self.duration_secs))
            .await
            .context("BLE scan failed")?;
        debug!("scan command: discovered {} device(s)", devices.len());

        if devices.is_empty() {
            println!("No devices found.");
            return Ok(());
        }

        DeviceList(devices).print();
        Ok(())
    }
}
