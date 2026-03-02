use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ble_transport::{BleManager, DiscoveredDevice};
use hw_wallet::WalletError;
use hw_wallet::ble::{
    SessionBootstrapOptions, SessionPhase, advance_session_bootstrap, backend_from_session,
    connect_trezor_device, scan_profile_until_match, trezor_profile, workflow_with_storage,
};
use tokio::time::timeout;
use tracing::debug;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{
    FileStorage, HostConfig, PairingMethod as ThpPairingMethod, ThpBackend, ThpWorkflow,
};

use crate::config::{default_host_name, default_storage_path};
use crate::pairing::CliPairingController;
use crate::ui::prompt_line;

#[derive(Debug, Clone)]
pub struct ConnectWorkflowOptions {
    pub scan_timeout_secs: u64,
    pub thp_timeout_secs: u64,
    pub device_id: Option<String>,
    pub storage_path: Option<PathBuf>,
    pub host_name: Option<String>,
    pub app_name: String,
    pub skip_pairing: bool,
}

pub fn select_device(
    mut devices: Vec<DiscoveredDevice>,
    device_id: Option<&str>,
) -> Result<DiscoveredDevice> {
    debug!(
        "select_device: candidates={}, device_id_filter={:?}",
        devices.len(),
        device_id
    );
    if let Some(query) = device_id {
        if let Some(idx) = devices.iter().position(|d| d.info().id == query) {
            debug!("select_device: exact match for device_id={}", query);
            return Ok(devices.remove(idx));
        }

        let matches: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, device)| device.info().id.contains(query))
            .map(|(idx, _)| idx)
            .collect();

        if matches.len() == 1 {
            debug!(
                "select_device: partial match for device_id={} resolved to index={}",
                query, matches[0]
            );
            return Ok(devices.remove(matches[0]));
        }

        if matches.is_empty() {
            bail!("no scanned device matched --device-id '{}'", query);
        }
        bail!(
            "--device-id '{}' matched multiple devices; use a full id",
            query
        );
    }

    if devices.len() == 1 {
        return Ok(devices.remove(0));
    }

    println!("Multiple devices found:");
    for (idx, device) in devices.iter().enumerate() {
        let info = device.info();
        println!(
            "  {}. id={} name={} rssi={}",
            idx + 1,
            info.id,
            info.name.as_deref().unwrap_or("unknown"),
            info.rssi
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }

    let selected = prompt_device_selection(devices.len())?;
    Ok(devices.remove(selected))
}

pub fn print_discovered_devices(devices: &[DiscoveredDevice]) {
    println!("Found {} device(s):", devices.len());
    for (idx, device) in devices.iter().enumerate() {
        let info = device.info();
        println!(
            "  {}. id={} name={} rssi={}",
            idx + 1,
            info.id,
            info.name.as_deref().unwrap_or("unknown"),
            info.rssi
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
}

fn prompt_device_selection(total: usize) -> Result<usize> {
    loop {
        let input = prompt_line("Select device number: ")?;
        let number = input
            .parse::<usize>()
            .with_context(|| format!("invalid selection '{}'", input))?;
        if number == 0 || number > total {
            println!("Please enter a number between 1 and {}.", total);
            continue;
        }
        return Ok(number - 1);
    }
}

pub async fn connect_workflow(
    options: ConnectWorkflowOptions,
    operation_label: &str,
    peer_removed_hint: &str,
) -> Result<(ThpWorkflow<BleBackend>, PathBuf)> {
    let profile = trezor_profile()?;
    let manager = BleManager::new().await.context("BLE manager init failed")?;
    debug!(
        "{} profile: id={}, service_uuid={}",
        operation_label, profile.id, profile.service_uuid
    );

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, options.scan_timeout_secs
    );
    let devices = scan_profile_until_match(
        &manager,
        profile,
        Duration::from_secs(options.scan_timeout_secs),
        options.device_id.as_deref(),
    )
    .await
    .context("BLE scan failed")?;
    tracing::info!("scan complete: discovered {} device(s)", devices.len());
    if devices.is_empty() {
        bail!("no devices found");
    }

    let selected = select_device(devices, options.device_id.as_deref())?;
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
        Duration::from_secs(options.thp_timeout_secs),
        connect_trezor_device(selected, profile),
    )
    .await
    {
        Err(_) => bail!(
            "opening BLE session timed out after {}s",
            options.thp_timeout_secs
        ),
        Ok(Ok(session)) => session,
        Ok(Err(WalletError::PeerRemovedPairingInfo)) => {
            bail!(
                "opening BLE session failed: peer removed pairing information. {}",
                peer_removed_hint
            );
        }
        Ok(Err(err)) => return Err(err).context("opening BLE session failed"),
    };
    println!("BLE session established.");
    debug!("BLE session established");
    let backend = backend_from_session(session, Duration::from_secs(options.thp_timeout_secs));
    debug!(
        "configured THP backend response timeout: {:?}",
        backend.handshake_timeout()
    );

    let storage_path = options.storage_path.unwrap_or_else(default_storage_path);
    let host_name = options.host_name.unwrap_or_else(default_host_name);
    let mut config = HostConfig::new(host_name, options.app_name);
    config.pairing_methods = if options.skip_pairing {
        vec![ThpPairingMethod::SkipPairing]
    } else {
        vec![ThpPairingMethod::CodeEntry]
    };
    let storage = Arc::new(FileStorage::new(storage_path.clone()));
    let workflow = workflow_with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;
    debug!(
        "{} workflow initialized with persisted host state",
        operation_label
    );

    Ok((workflow, storage_path))
}

pub async fn ensure_session_ready<B>(
    workflow: &mut ThpWorkflow<B>,
    thp_timeout_secs: u64,
    operation_label: &str,
) -> Result<()>
where
    B: ThpBackend + Send,
{
    println!("Preparing authenticated wallet session...");
    let mut session_ready = false;
    let options = SessionBootstrapOptions {
        thp_timeout: Duration::from_secs(thp_timeout_secs),
        try_to_unlock: true,
        passphrase: None,
        on_device: false,
        derive_cardano: false,
        ..SessionBootstrapOptions::default()
    };
    loop {
        let step = advance_session_bootstrap(workflow, &mut session_ready, &options)
            .await
            .with_context(|| {
                format!("failed to prepare authenticated wallet session for {operation_label}")
            })?;
        match step {
            SessionPhase::Ready => break,
            SessionPhase::NeedsPairingCode => {
                println!("Pairing required. Complete code-entry pairing on this terminal.");
                let controller = CliPairingController;
                workflow
                    .pairing(Some(&controller))
                    .await
                    .with_context(|| format!("pairing failed during {operation_label} workflow"))?;
            }
            other => bail!(
                "{operation_label} workflow reached unexpected step: {:?}",
                other
            ),
        }
    }

    Ok(())
}

pub async fn connect_ready_workflow(
    options: ConnectWorkflowOptions,
    operation_label: &str,
    peer_removed_hint: &str,
) -> Result<ThpWorkflow<BleBackend>> {
    let thp_timeout_secs = options.thp_timeout_secs;
    let (mut workflow, _) = connect_workflow(options, operation_label, peer_removed_hint).await?;
    ensure_session_ready(&mut workflow, thp_timeout_secs, operation_label).await?;
    Ok(workflow)
}
