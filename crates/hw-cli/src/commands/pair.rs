use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ble_transport::BleManager;
use hw_wallet::ble::{
    backend_from_session, connect_trezor_device, create_channel_with_retry,
    create_session_with_retry, handshake_with_retry, scan_profile_until_match, trezor_profile,
    workflow_with_storage, CREATE_CHANNEL_ATTEMPTS, CREATE_SESSION_ATTEMPTS, HANDSHAKE_ATTEMPTS,
    RETRY_DELAY,
};
use hw_wallet::WalletError;
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{FileStorage, HostConfig, PairingMethod as ThpPairingMethod, Phase};

use crate::cli::{PairArgs, PairingMethod};
use crate::commands::common::select_device;
use crate::commands::session;
use crate::config::{default_host_name, default_storage_path};
use crate::pairing::CliPairingController;

pub async fn run(args: PairArgs) -> Result<()> {
    info!(
        "pair command started: pairing_method={:?}, scan_timeout_secs={}, thp_timeout_secs={}, interactive={}, force={}",
        args.pairing_method, args.timeout_secs, args.thp_timeout_secs, args.interactive, args.force
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

    println!(
        "Creating THP channel (may take up to ~{}s with retries)...",
        args.thp_timeout_secs * 3
    );
    let channel_attempt =
        create_channel_with_retry(&mut workflow, CREATE_CHANNEL_ATTEMPTS, RETRY_DELAY)
            .await
            .context("create-channel failed")?;
    if channel_attempt > 1 {
        info!(
            "create-channel succeeded on retry attempt {}",
            channel_attempt
        );
    }
    info!("THP channel created");
    println!("Performing THP handshake...");
    let try_to_unlock = args.interactive;
    let handshake_attempt = handshake_with_retry(
        &mut workflow,
        try_to_unlock,
        HANDSHAKE_ATTEMPTS,
        RETRY_DELAY,
    )
    .await
    .context("handshake failed")?;
    if handshake_attempt > 1 {
        info!("handshake succeeded on retry attempt {}", handshake_attempt);
    }
    info!(
        "handshake complete: phase={:?}, paired={}",
        workflow.state().phase(),
        workflow.state().is_paired()
    );

    match workflow.state().phase() {
        Phase::Pairing => {
            if workflow.state().is_paired() {
                println!("Confirming THP connection...");
                workflow
                    .pairing(None)
                    .await
                    .context("connection confirmation failed")?;
                println!("Connection confirmed.");
                info!("paired handshake connection flow completed");
            } else {
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
            }
        }
        Phase::Paired => {
            println!("Device already paired (or auto-paired).");
            info!(
                "device already paired or autopaired; pairing-request (host/app label update) was not sent in this run"
            );
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

    if args.interactive {
        println!("Creating wallet session...");
        create_session_with_retry(
            &mut workflow,
            None,
            false,
            false,
            CREATE_SESSION_ATTEMPTS,
            RETRY_DELAY,
        )
        .await
        .context("create-session failed before entering interactive mode")?;
        let session_result = session::run(&mut workflow).await;

        println!("Closing BLE session...");
        if let Err(err) = workflow.backend_mut().link_mut().disconnect().await {
            debug!("BLE disconnect failed during interactive shutdown: {err}");
        }

        session_result?;
    }

    Ok(())
}
