use anyhow::{Context, Result, bail};
use hw_wallet::chain::{Chain, ResolvedDerivationPath};
use tracing::info;
use trezor_connect::thp::{GetAddressRequest, ThpBackend, ThpWorkflow};

use crate::cli::AddressArgs;
use crate::commands::common::{connect_ready_workflow, print_address_response, print_requesting};

pub async fn run(args: AddressArgs, skip_pairing: bool) -> Result<()> {
    let resolved = ResolvedDerivationPath::resolve(args.chain, args.path.as_deref())?;
    info!(
        "address command started: chain={:?} path='{}' scan_timeout_secs={} thp_timeout_secs={} show_on_device={} include_public_key={} chunkify={}",
        resolved.chain,
        resolved.path,
        args.connect.timeout_secs,
        args.connect.thp_timeout_secs,
        args.show_on_device,
        args.include_public_key,
        args.chunkify
    );

    let mut workflow = connect_ready_workflow(&args.connect, skip_pairing, "address").await?;

    print_requesting(&format!("{:?} address", resolved.chain));
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

    print_address_response(
        &response.address,
        response.mac.as_deref(),
        response.public_key.as_deref(),
    );

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

#[cfg(test)]
mod tests {
    use super::*;

    use hw_wallet::ble::{
        BootstrapTarget, SessionBootstrap, SessionBootstrapOptions, SessionPhase,
        SessionRetryPolicy,
    };
    use trezor_connect::thp::HostConfig;
    use trezor_connect::thp::testing::MockBackend;

    #[tokio::test]
    async fn address_request_carries_cli_display_flags() {
        let backend = MockBackend::paired_connection_flow().with_transient_session_failure();
        let mut workflow = ThpWorkflow::new(backend, HostConfig::new("test-host", "hw-core/cli"));
        let options = SessionBootstrapOptions {
            try_to_unlock: true,
            retry_policy: SessionRetryPolicy {
                retry_delay_ms: 1,
                ..SessionRetryPolicy::default()
            },
            ..SessionBootstrapOptions::default()
        };
        let phase = workflow
            .advance_session_bootstrap(false, BootstrapTarget::Session, &options)
            .await
            .unwrap();
        assert_eq!(phase, SessionPhase::Ready);

        let path = vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
        let response = get_address_with_workflow(
            &mut workflow,
            Chain::Ethereum,
            path.clone(),
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
        assert_eq!(request.chain, Chain::Ethereum);
        assert_eq!(request.path, path);
        assert!(request.show_display);
        assert!(request.include_public_key);
        assert!(!request.chunkify);
    }
}
