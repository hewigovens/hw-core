use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ble_transport::BleManager;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ble::{
    backend_from_session, connect_trezor_device, create_channel_with_retry,
    scan_profile_until_match, trezor_profile, workflow_with_storage,
};
use hw_wallet::WalletError;
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{
    Chain, FileStorage, GetAddressRequest, HostConfig, PairingMethod as ThpPairingMethod, Phase,
};

use crate::cli::{AddressArgs, AddressCommand, AddressEthArgs};
use crate::commands::common::select_device;
use crate::config::{default_host_name, default_storage_path};

pub async fn run(args: AddressArgs) -> Result<()> {
    match args.command {
        AddressCommand::Eth(args) => run_eth(args).await,
    }
}

async fn run_eth(args: AddressEthArgs) -> Result<()> {
    let address_n = parse_bip32_path(&args.path)?;
    info!(
        "address command started: chain=ethereum path='{}' scan_timeout_secs={} thp_timeout_secs={} show_on_device={} include_public_key={} chunkify={}",
        args.path,
        args.timeout_secs,
        args.thp_timeout_secs,
        args.show_on_device,
        args.include_public_key,
        args.chunkify
    );

    let profile = trezor_profile()?;
    let manager = BleManager::new().await.context("BLE manager init failed")?;
    debug!(
        "address profile: id={}, service_uuid={}",
        profile.id, profile.service_uuid
    );

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
                "opening BLE session failed: peer removed pairing information. Remove this Trezor from macOS Bluetooth settings, then pair again."
            );
        }
        Ok(Err(err)) => return Err(err).context("opening BLE session failed"),
    };
    println!("BLE session established.");
    let backend = backend_from_session(session, Duration::from_secs(args.thp_timeout_secs));

    let storage_path = args.storage_path.unwrap_or_else(default_storage_path);
    let host_name = args.host_name.unwrap_or_else(default_host_name);
    let mut config = HostConfig::new(host_name, args.app_name);
    config.pairing_methods = vec![ThpPairingMethod::CodeEntry];
    let storage = Arc::new(FileStorage::new(storage_path.clone()));
    let mut workflow = workflow_with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;
    debug!("address workflow initialized with persisted host state");

    println!(
        "Creating THP channel (may take up to ~{}s with retries)...",
        args.thp_timeout_secs * 3
    );
    create_channel_with_retry(&mut workflow, 3, Duration::from_millis(800))
        .await
        .context("create-channel failed")?;
    println!("Performing THP handshake...");
    workflow
        .handshake(false)
        .await
        .context("handshake failed")?;

    match workflow.state().phase() {
        Phase::Paired => {}
        Phase::Pairing => {
            bail!("device is not paired for this host; run `hw-cli pair` first");
        }
        other => {
            bail!("unexpected workflow phase after handshake: {:?}", other);
        }
    }

    println!("Creating wallet session...");
    workflow
        .create_session(None, false, false)
        .await
        .context("create-session failed")?;

    println!("Requesting Ethereum address from device...");
    let request = GetAddressRequest::ethereum(address_n)
        .with_show_display(args.show_on_device)
        .with_chunkify(args.chunkify)
        .with_include_public_key(args.include_public_key);
    let response = workflow
        .get_address(request)
        .await
        .context("get-address failed")?;

    if response.chain != Chain::Ethereum {
        bail!("unexpected response chain");
    }

    println!("Address: {}", response.address);
    if let Some(mac) = response.mac {
        println!("MAC: {}", hex::encode(mac));
    }
    if let Some(public_key) = response.public_key {
        println!("Public key: {}", public_key);
    }

    Ok(())
}
