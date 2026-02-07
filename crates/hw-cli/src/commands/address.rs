use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ble_transport::BleManager;
use hw_wallet::ble::{
    backend_from_session, connect_trezor_device, create_channel_with_retry, handshake_with_retry,
    scan_profile_until_match, trezor_profile, workflow_with_storage,
};
use hw_wallet::chain::{resolve_derivation_path, Chain, ResolvedDerivationPath};
use hw_wallet::WalletError;
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{
    Chain as ThpChain, FileStorage, GetAddressRequest, HostConfig,
    PairingMethod as ThpPairingMethod, Phase,
};

use crate::cli::{AddressArgs, DEFAULT_ETH_BIP32_PATH};
use crate::commands::common::select_device;
use crate::config::{default_host_name, default_storage_path};

pub async fn run(args: AddressArgs) -> Result<()> {
    let resolved = ResolvedAddressTarget::from_args(&args)?;
    if resolved.chain == Chain::Bitcoin {
        bail!(
            "BTC address flow is not implemented yet. Try `address --chain eth` or `address --path {}`.",
            DEFAULT_ETH_BIP32_PATH
        );
    }
    info!(
        "address command started: chain={:?} path='{}' scan_timeout_secs={} thp_timeout_secs={} show_on_device={} include_public_key={} chunkify={}",
        resolved.chain,
        resolved.path,
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
    let handshake_attempt = handshake_with_retry(&mut workflow, false, 2, Duration::from_millis(800))
        .await
        .context("handshake failed")?;
    if handshake_attempt > 1 {
        info!("handshake succeeded on retry attempt {}", handshake_attempt);
    }

    match workflow.state().phase() {
        Phase::Paired => {}
        Phase::Pairing => {
            if workflow.state().is_paired() {
                println!("Confirming THP connection...");
                workflow
                    .pairing(None)
                    .await
                    .context("connection confirmation failed")?;
            } else {
                bail!("device is not paired for this host; run `hw-cli pair` first");
            }
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

    println!("Requesting {:?} address from device...", resolved.chain);
    let request = GetAddressRequest::ethereum(resolved.path_indices)
        .with_show_display(args.show_on_device)
        .with_chunkify(args.chunkify)
        .with_include_public_key(args.include_public_key);
    let response = workflow
        .get_address(request)
        .await
        .context("get-address failed")?;

    if response.chain != ThpChain::Ethereum {
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

#[derive(Debug)]
struct ResolvedAddressTarget {
    chain: Chain,
    path: String,
    path_indices: Vec<u32>,
}

impl ResolvedAddressTarget {
    fn from_args(args: &AddressArgs) -> Result<Self> {
        let resolved = resolve_derivation_path(args.chain, args.path.as_deref())?;
        Ok(Self::from_wallet_resolved(resolved))
    }
}

impl ResolvedAddressTarget {
    fn from_wallet_resolved(resolved: ResolvedDerivationPath) -> Self {
        Self {
            chain: resolved.chain,
            path: resolved.path,
            path_indices: resolved.path_indices,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hw_wallet::chain::DEFAULT_BTC_BIP32_PATH;

    fn args(chain: Option<Chain>, path: Option<&str>) -> AddressArgs {
        AddressArgs {
            chain,
            path: path.map(ToOwned::to_owned),
            show_on_device: true,
            include_public_key: false,
            chunkify: false,
            timeout_secs: 60,
            thp_timeout_secs: 60,
            device_id: None,
            storage_path: None,
            host_name: None,
            app_name: "hw-core/cli".to_string(),
        }
    }

    #[test]
    fn defaults_to_eth_default_path() {
        let resolved = ResolvedAddressTarget::from_args(&args(None, None)).unwrap();
        assert_eq!(resolved.chain, Chain::Ethereum);
        assert_eq!(resolved.path, DEFAULT_ETH_BIP32_PATH);
    }

    #[test]
    fn defaults_to_btc_path_when_chain_is_btc() {
        let resolved = ResolvedAddressTarget::from_args(&args(Some(Chain::Bitcoin), None)).unwrap();
        assert_eq!(resolved.chain, Chain::Bitcoin);
        assert_eq!(resolved.path, DEFAULT_BTC_BIP32_PATH);
    }

    #[test]
    fn infers_chain_from_eth_path() {
        let resolved =
            ResolvedAddressTarget::from_args(&args(None, Some("m/44'/60'/0'/0/0"))).unwrap();
        assert_eq!(resolved.chain, Chain::Ethereum);
    }

    #[test]
    fn rejects_chain_path_mismatch() {
        let err =
            ResolvedAddressTarget::from_args(&args(Some(Chain::Ethereum), Some("m/84'/0'/0'/0/0")))
                .unwrap_err();
        assert!(err.to_string().contains("chain/path mismatch"));
    }
}
