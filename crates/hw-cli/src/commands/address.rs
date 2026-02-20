use anyhow::{Context, Result, bail};
use hw_wallet::chain::{Chain, ResolvedDerivationPath, resolve_derivation_path};
use tracing::info;
use trezor_connect::thp::{GetAddressRequest, ThpBackend, ThpWorkflow};

use crate::cli::AddressArgs;
use crate::commands::common::{ConnectWorkflowOptions, connect_ready_workflow};

pub async fn run(args: AddressArgs) -> Result<()> {
    let resolved = ResolvedAddressTarget::from_args(&args)?;
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

    let mut workflow = connect_ready_workflow(
        ConnectWorkflowOptions {
            scan_timeout_secs: args.timeout_secs,
            thp_timeout_secs: args.thp_timeout_secs,
            device_id: args.device_id.clone(),
            storage_path: args.storage_path.clone(),
            host_name: args.host_name.clone(),
            app_name: args.app_name.clone(),
        },
        "address",
        "Remove this Trezor from macOS Bluetooth settings, then pair again.",
    )
    .await?;

    println!("Requesting {:?} address from device...", resolved.chain);
    let response = get_address_with_workflow(
        &mut workflow,
        resolved.chain,
        resolved.path_indices.clone(),
        args.show_on_device,
        args.include_public_key,
        args.chunkify,
    )
    .await?;

    if response.chain != resolved.chain {
        bail!(
            "unexpected response chain: expected {:?}, got {:?}",
            resolved.chain,
            response.chain
        );
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

async fn get_address_with_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    chain: Chain,
    path_indices: Vec<u32>,
    show_on_device: bool,
    include_public_key: bool,
    chunkify: bool,
) -> Result<trezor_connect::thp::GetAddressResponse>
where
    B: ThpBackend + Send,
{
    let request = build_get_address_request(chain, path_indices)
        .with_show_display(show_on_device)
        .with_chunkify(chunkify)
        .with_include_public_key(include_public_key);
    workflow
        .get_address(request)
        .await
        .context("get-address failed")
}

fn build_get_address_request(chain: Chain, path_indices: Vec<u32>) -> GetAddressRequest {
    match chain {
        Chain::Ethereum => GetAddressRequest::ethereum(path_indices),
        Chain::Bitcoin => GetAddressRequest::bitcoin(path_indices),
        Chain::Solana => GetAddressRequest::solana(path_indices),
    }
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

    use crate::commands::test_support::{
        MockBackend, canned_eth_address_response, default_test_host_config,
    };
    use hw_wallet::ble::{SessionBootstrapOptions, SessionPhase, advance_session_bootstrap};
    use hw_wallet::chain::{
        DEFAULT_BTC_BIP32_PATH, DEFAULT_ETH_BIP32_PATH, DEFAULT_SOL_BIP32_PATH,
    };
    use std::time::Duration;
    use trezor_connect::thp::{Chain as ThpChain, ThpWorkflow};

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
    fn defaults_to_sol_path_when_chain_is_sol() {
        let resolved = ResolvedAddressTarget::from_args(&args(Some(Chain::Solana), None)).unwrap();
        assert_eq!(resolved.chain, Chain::Solana);
        assert_eq!(resolved.path, DEFAULT_SOL_BIP32_PATH);
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

    #[tokio::test]
    async fn address_flow_orchestrates_handshake_confirmation_and_session_retry() {
        let backend = MockBackend::paired_with_session_retry(b"addr-test")
            .with_get_address_response(canned_eth_address_response(
                "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE",
            ));
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
        let response = get_address_with_workflow(
            &mut workflow,
            Chain::Ethereum,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            true,
            true,
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            response.address,
            "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE"
        );
        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.credential_calls, 1);
        assert_eq!(backend.counters.create_session_calls, 2);
        assert_eq!(backend.counters.get_address_calls, 1);
        let request = backend.last_get_address_request.as_ref().unwrap();
        assert_eq!(request.chain, ThpChain::Ethereum);
        assert_eq!(
            request.path,
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
        );
        assert!(request.show_display);
        assert!(request.include_public_key);
    }
}
