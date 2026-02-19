use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ble_transport::BleManager;
use hw_wallet::WalletError;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::ble::{
    SessionBootstrapOptions, SessionPhase, advance_session_bootstrap, backend_from_session,
    connect_trezor_device, scan_profile_until_match, trezor_profile, workflow_with_storage,
};
use hw_wallet::chain::{Chain, DEFAULT_BTC_BIP32_PATH, DEFAULT_ETH_BIP32_PATH};
use hw_wallet::eip712::{build_sign_typed_data_request, normalize_typed_data_signature};
use hw_wallet::message::{build_sign_message_request, normalize_message_signature};
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::thp::{
    FileStorage, HostConfig, PairingMethod as ThpPairingMethod, SignMessageRequest,
    SignMessageResponse, SignTypedDataRequest, SignTypedDataResponse, ThpBackend, ThpWorkflow,
};

use crate::cli::{
    EthSignMessageType, SignMessageArgs, SignMessageBtcArgs, SignMessageCommand, SignMessageEthArgs,
};
use crate::commands::common::select_device;
use crate::config::{default_host_name, default_storage_path};
use crate::pairing::CliPairingController;

enum EthSignMessageRequestKind {
    Eip191(SignMessageRequest),
    Eip712(SignTypedDataRequest),
}

pub async fn run(args: SignMessageArgs) -> Result<()> {
    match args.command {
        SignMessageCommand::Eth(args) => run_eth(args).await,
        SignMessageCommand::Btc(args) => run_btc(args).await,
    }
}

async fn run_eth(args: SignMessageEthArgs) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_ETH_BIP32_PATH)
        .to_string();
    let path_indices = parse_bip32_path(&path)?;
    let request = build_eth_sign_request(&args, path_indices)
        .context("failed to build ETH sign-message request")?;

    let mut workflow = connect_ready_workflow(
        args.timeout_secs,
        args.thp_timeout_secs,
        args.device_id.as_deref(),
        args.storage_path,
        args.host_name,
        args.app_name,
    )
    .await?;

    match request {
        EthSignMessageRequestKind::Eip191(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip191 path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
                path, args.hex, args.chunkify, args.timeout_secs, args.thp_timeout_secs
            );
            println!("Requesting ETH message signature from device...");
            let response = sign_message_with_workflow(&mut workflow, request).await?;
            let normalized = normalize_message_signature(&response)?;
            print_signature_response(&response.address, &normalized.value, &response.signature);
        }
        EthSignMessageRequestKind::Eip712(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip712 path='{}' scan_timeout_secs={} thp_timeout_secs={}",
                path, args.timeout_secs, args.thp_timeout_secs
            );
            println!("Requesting ETH typed-data signature from device...");
            let response = sign_typed_data_with_workflow(&mut workflow, request).await?;
            let normalized = normalize_typed_data_signature(&response)?;
            print_signature_response(&response.address, &normalized, &response.signature);
        }
    }

    Ok(())
}

async fn run_btc(args: SignMessageBtcArgs) -> Result<()> {
    let path = args
        .path
        .unwrap_or_else(|| DEFAULT_BTC_BIP32_PATH.to_string());
    let path_indices = parse_bip32_path(&path)?;
    let request = build_sign_message_request(
        Chain::Bitcoin,
        path_indices,
        &args.message,
        args.hex,
        args.chunkify,
    )
    .context("failed to build BTC sign-message request")?;

    info!(
        "sign-message command started: chain=bitcoin path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
        path, args.hex, args.chunkify, args.timeout_secs, args.thp_timeout_secs
    );

    let mut workflow = connect_ready_workflow(
        args.timeout_secs,
        args.thp_timeout_secs,
        args.device_id.as_deref(),
        args.storage_path,
        args.host_name,
        args.app_name,
    )
    .await?;

    println!("Requesting BTC message signature from device...");
    let response = sign_message_with_workflow(&mut workflow, request).await?;
    let normalized = normalize_message_signature(&response)?;
    print_signature_response(&response.address, &normalized.value, &response.signature);
    Ok(())
}

fn build_eth_sign_request(
    args: &SignMessageEthArgs,
    path: Vec<u32>,
) -> Result<EthSignMessageRequestKind> {
    match args.message_type {
        EthSignMessageType::Eip191 => {
            if args.data_file.is_some() {
                bail!("--data-file is only valid with --type eip712");
            }
            let message = args
                .message
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--message is required for --type eip191"))?;
            let request = build_sign_message_request(
                Chain::Ethereum,
                path,
                message,
                args.hex,
                args.chunkify,
            )?;
            Ok(EthSignMessageRequestKind::Eip191(request))
        }
        EthSignMessageType::Eip712 => {
            if args.message.is_some() || args.hex || args.chunkify {
                bail!("--message/--hex/--chunkify are only valid with --type eip191");
            }
            let data_file = args
                .data_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--data-file is required for --type eip712"))?;
            let data = std::fs::read_to_string(data_file)
                .with_context(|| format!("reading typed-data file: {}", data_file.display()))?;
            let request = build_sign_typed_data_request(path, &data, args.metamask_v4_compat)?;
            Ok(EthSignMessageRequestKind::Eip712(request))
        }
    }
}

fn print_signature_response(address: &str, normalized_signature: &str, raw_signature: &[u8]) {
    println!("Address: {}", address);
    println!("Signature: {}", normalized_signature);
    println!("Signature (hex): 0x{}", hex::encode(raw_signature));
}

async fn connect_ready_workflow(
    timeout_secs: u64,
    thp_timeout_secs: u64,
    device_id: Option<&str>,
    storage_path: Option<std::path::PathBuf>,
    host_name: Option<String>,
    app_name: String,
) -> Result<ThpWorkflow<trezor_connect::ble::BleBackend>> {
    let profile = trezor_profile()?;
    let manager = BleManager::new().await.context("BLE manager init failed")?;
    debug!(
        "sign-message profile: id={}, service_uuid={}",
        profile.id, profile.service_uuid
    );

    println!(
        "Scanning for {} devices for {}s...",
        profile.name, timeout_secs
    );
    let devices = scan_profile_until_match(
        &manager,
        profile,
        Duration::from_secs(timeout_secs),
        device_id,
    )
    .await
    .context("BLE scan failed")?;
    info!("scan complete: discovered {} device(s)", devices.len());
    if devices.is_empty() {
        bail!("no devices found");
    }

    let selected = select_device(devices, device_id)?;
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
        Duration::from_secs(thp_timeout_secs),
        connect_trezor_device(selected, profile),
    )
    .await
    {
        Err(_) => bail!("opening BLE session timed out after {}s", thp_timeout_secs),
        Ok(Ok(session)) => session,
        Ok(Err(WalletError::PeerRemovedPairingInfo)) => {
            bail!(
                "opening BLE session failed: peer removed pairing information. Remove this Trezor from macOS Bluetooth settings, then pair again."
            );
        }
        Ok(Err(err)) => return Err(err).context("opening BLE session failed"),
    };
    println!("BLE session established.");
    let backend = backend_from_session(session, Duration::from_secs(thp_timeout_secs));

    let storage_path = storage_path.unwrap_or_else(default_storage_path);
    let host_name = host_name.unwrap_or_else(default_host_name);
    let mut config = HostConfig::new(host_name, app_name);
    config.pairing_methods = vec![ThpPairingMethod::CodeEntry];
    let storage = Arc::new(FileStorage::new(storage_path));
    let mut workflow = workflow_with_storage(backend, config, storage)
        .await
        .context("workflow setup failed")?;

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
        let step = advance_session_bootstrap(&mut workflow, &mut session_ready, &options)
            .await
            .context("failed to prepare authenticated wallet session")?;
        match step {
            SessionPhase::Ready => break,
            SessionPhase::NeedsPairingCode => {
                println!("Pairing required. Complete code-entry pairing on this terminal.");
                let controller = CliPairingController;
                workflow
                    .pairing(Some(&controller))
                    .await
                    .context("pairing failed during sign-message workflow")?;
            }
            other => bail!("sign-message workflow reached unexpected step: {:?}", other),
        }
    }

    Ok(workflow)
}

async fn sign_message_with_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignMessageRequest,
) -> Result<SignMessageResponse>
where
    B: ThpBackend + Send,
{
    workflow
        .sign_message(request)
        .await
        .context("sign-message failed")
}

async fn sign_typed_data_with_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    request: SignTypedDataRequest,
) -> Result<SignTypedDataResponse>
where
    B: ThpBackend + Send,
{
    workflow
        .sign_typed_data(request)
        .await
        .context("sign-message failed for --type eip712")
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::commands::test_support::{
        MockBackend, canned_btc_message_sign_response, canned_eth_message_sign_response,
        canned_eth_typed_data_sign_response, default_test_host_config,
    };
    use trezor_connect::thp::{Chain as ThpChain, ThpWorkflow};

    #[tokio::test]
    async fn sign_message_eth_flow_uses_ethereum_chain() {
        let backend = MockBackend::paired_with_session_retry(b"msg-eth-test")
            .with_sign_message_response(canned_eth_message_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);

        let request = build_sign_message_request(
            Chain::Ethereum,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            "hello",
            false,
            true,
        )
        .unwrap();
        let response = sign_message_with_workflow(&mut workflow, request)
            .await
            .unwrap();

        assert_eq!(response.chain, ThpChain::Ethereum);
        assert_eq!(response.signature.len(), 65);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.sign_message_calls, 1);
        let request = backend.last_sign_message_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Ethereum);
        assert!(request.chunkify);
    }

    #[tokio::test]
    async fn sign_message_btc_flow_uses_bitcoin_chain() {
        let backend = MockBackend::paired_with_session_retry(b"msg-btc-test")
            .with_sign_message_response(canned_btc_message_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);

        let request = build_sign_message_request(
            Chain::Bitcoin,
            vec![0x8000_002c, 0x8000_0000, 0x8000_0000],
            "68656c6c6f",
            true,
            false,
        )
        .unwrap();
        let response = sign_message_with_workflow(&mut workflow, request)
            .await
            .unwrap();

        assert_eq!(response.chain, ThpChain::Bitcoin);
        assert_eq!(response.signature.len(), 65);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.sign_message_calls, 1);
        let request = backend.last_sign_message_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Bitcoin);
    }

    #[tokio::test]
    async fn sign_message_eth_eip712_flow_uses_ethereum_chain() {
        let backend = MockBackend::paired_with_session_retry(b"msg-typed-eth-test")
            .with_sign_typed_data_response(canned_eth_typed_data_sign_response());
        let config = default_test_host_config();
        let mut workflow = ThpWorkflow::new(backend, config);

        let mut session_ready = false;
        let step = advance_session_bootstrap(
            &mut workflow,
            &mut session_ready,
            &SessionBootstrapOptions {
                thp_timeout: Duration::from_secs(60),
                try_to_unlock: true,
                passphrase: None,
                on_device: false,
                derive_cardano: false,
                ..SessionBootstrapOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(step, SessionPhase::Ready);

        let request = build_sign_typed_data_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            r#"{
                "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Mail": [
                        { "name": "from", "type": "address" },
                        { "name": "contents", "type": "string" }
                    ]
                },
                "primaryType": "Mail",
                "domain": { "name": "Ether Mail" },
                "message": { "from": "0x1111111111111111111111111111111111111111", "contents": "hello" }
            }"#,
            true,
        )
        .unwrap();
        let response = sign_typed_data_with_workflow(&mut workflow, request)
            .await
            .unwrap();

        assert_eq!(response.chain, ThpChain::Ethereum);
        assert_eq!(response.signature.len(), 65);
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.sign_typed_data_calls, 1);
        let request = backend.last_sign_typed_data_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Ethereum);
    }
}
