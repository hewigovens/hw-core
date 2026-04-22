use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use ble_transport::{BleProfile, BleSession};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::ThpWorkflow;
use trezor_connect::thp::types::{HostConfig, PairingMethod};

#[tokio::main]
async fn main() -> Result<()> {
    let profile =
        BleProfile::trezor_safe7().ok_or_else(|| anyhow!("trezor_safe7 profile not enabled"))?;
    let manager = ble_transport::BleManager::new().await?;

    println!("Scanning for {:?}…", profile.name);
    let devices = manager
        .scan_profile(profile, Duration::from_secs(5))
        .await?;

    let device = devices
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no Trezor devices found"))?;

    let info = device.info();
    println!("Connecting to {} ({:?})", info.id, info.name);

    let (info, peripheral) = device.into_parts();
    let session = BleSession::new(peripheral, profile, info)
        .await
        .context("opening BLE session")?;

    let backend = BleBackend::from_session(session);

    let mut host_config = HostConfig::new("Host Demo", "hw-core example");
    host_config.pairing_methods.push(PairingMethod::QrCode);

    let mut workflow = ThpWorkflow::new(backend, host_config);

    workflow.create_channel().await?;
    workflow.handshake(false).await?;

    println!("State after handshake: {:?}", workflow.state());

    Ok(())
}
