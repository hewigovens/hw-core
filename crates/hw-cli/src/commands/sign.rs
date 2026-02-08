use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ble_transport::BleManager;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ble::{
    backend_from_session, connect_trezor_device, prepare_ready_workflow, scan_profile_until_match,
    trezor_profile, workflow_with_storage, ReadyWorkflowOptions,
};
use hw_wallet::eth::{build_sign_tx_request, parse_tx_json, verify_sign_tx_response};
use hw_wallet::WalletError;
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{
    FileStorage, HostConfig, PairingMethod as ThpPairingMethod, SignTxRequest, ThpBackend,
    ThpWorkflow,
};

use crate::cli::{SignArgs, SignCommand, SignEthArgs};
use crate::commands::common::select_device;
use crate::config::{default_host_name, default_storage_path};

pub async fn run(args: SignArgs) -> Result<()> {
    match args.command {
        SignCommand::Eth(args) => run_eth(args).await,
    }
}

async fn run_eth(args: SignEthArgs) -> Result<()> {
    let path = parse_bip32_path(&args.path)?;
    let tx_json = if let Some(path) = args.tx.strip_prefix('@') {
        std::fs::read_to_string(path).with_context(|| format!("reading tx file: {path}"))?
    } else {
        args.tx.clone()
    };

    let tx = parse_tx_json(&tx_json).context("failed to parse tx JSON")?;
    info!(
        "sign command started: chain=ethereum path='{}' to={} chain_id={} scan_timeout_secs={} thp_timeout_secs={}",
        args.path, tx.to, tx.chain_id, args.timeout_secs, args.thp_timeout_secs
    );
    let request = build_sign_tx_request(path, tx).context("failed to build sign request")?;

    let profile = trezor_profile()?;
    let manager = BleManager::new().await.context("BLE manager init failed")?;
    debug!(
        "sign profile: id={}, service_uuid={}",
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
    let storage = Arc::new(FileStorage::new(storage_path));
    let mut workflow = workflow_with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;
    debug!("sign workflow initialized with persisted host state");

    println!("Preparing authenticated wallet session...");
    prepare_ready_workflow(
        &mut workflow,
        &ReadyWorkflowOptions {
            thp_timeout: Duration::from_secs(args.thp_timeout_secs),
            try_to_unlock: false,
            passphrase: None,
            on_device: false,
            derive_cardano: false,
        },
    )
    .await
    .context("failed to prepare authenticated wallet session")?;

    println!("Requesting ETH transaction signature from device...");
    let response = sign_tx_with_workflow(&mut workflow, request.clone()).await?;
    println!("v: {}", response.v);
    println!("r: 0x{}", hex::encode(&response.r));
    println!("s: 0x{}", hex::encode(&response.s));
    if let Ok(verification) = verify_sign_tx_response(&request, &response) {
        println!("tx_hash: 0x{}", hex::encode(verification.tx_hash));
        println!("recovered_address: {}", verification.recovered_address);
    }

    Ok(())
}

async fn sign_tx_with_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTxRequest,
) -> Result<trezor_connect::thp::SignTxResponse>
where
    B: ThpBackend + Send,
{
    workflow.sign_tx(request).await.context("sign-tx failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::commands::test_support::{
        canned_eth_sign_response, default_test_host_config, MockBackend,
    };
    use trezor_connect::thp::{Chain as ThpChain, ThpWorkflow};

    #[tokio::test]
    async fn sign_flow_orchestrates_handshake_confirmation_and_session_retry() {
        let backend = MockBackend::paired_with_session_retry(b"sign-test")
            .with_sign_tx_response(canned_eth_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        prepare_ready_workflow(
            &mut workflow,
            &ReadyWorkflowOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: false,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
            },
        )
        .await
        .unwrap();
        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_nonce(vec![0])
            .with_gas_limit(vec![0x52, 0x08])
            .with_max_fee_per_gas(vec![1])
            .with_max_priority_fee(vec![1])
            .with_to("0x000000000000000000000000000000000000dead".into())
            .with_value(vec![0]);
        let response = sign_tx_with_workflow(&mut workflow, request).await.unwrap();

        assert_eq!(response.v, 0);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.credential_calls, 1);
        assert_eq!(backend.counters.create_session_calls, 2);
        assert_eq!(backend.counters.sign_tx_calls, 1);
        let request = backend.last_sign_tx_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Ethereum);
        assert_eq!(request.chain_id, 1);
    }
}
