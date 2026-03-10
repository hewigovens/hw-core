use anyhow::{Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::chain::{Chain, DEFAULT_BITCOIN_BIP32_PATH, DEFAULT_ETHEREUM_BIP32_PATH};
use hw_wallet::eip712::normalize_typed_data_signature;
use hw_wallet::message::{build_sign_message_request, normalize_message_signature};
use tracing::info;
use trezor_connect::thp::{
    SignMessageRequest, SignMessageResponse, SignTypedDataRequest, SignTypedDataResponse,
    ThpBackend, ThpWorkflow,
};

use self::eth_request::{EthSignRequest, build_eth_sign_request_from_args};
use crate::cli::{SignMessageArgs, SignMessageBtcArgs, SignMessageCommand, SignMessageEthArgs};
use crate::commands::common::{
    connect_ready_command_workflow, print_message_signature_response, print_requesting,
};

mod eth_request;

pub async fn run(args: SignMessageArgs, skip_pairing: bool) -> Result<()> {
    match args.command {
        SignMessageCommand::Eth(args) => run_eth(args, skip_pairing).await,
        SignMessageCommand::Btc(args) => run_btc(args, skip_pairing).await,
    }
}

async fn run_eth(args: SignMessageEthArgs, skip_pairing: bool) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_ETHEREUM_BIP32_PATH)
        .to_string();
    let path_indices = parse_bip32_path(&path)?;
    let request = build_eth_sign_request_from_args(&args, path_indices)
        .context("failed to build ETH sign-message request")?;

    let mut workflow = connect_ready_command_workflow(&args, skip_pairing, "sign-message").await?;

    match request {
        EthSignRequest::Message(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip191 path='{}' hex={} chunkify={} scan_timeout_secs={} thp_timeout_secs={}",
                path, args.hex, args.chunkify, args.timeout_secs, args.thp_timeout_secs
            );
            print_requesting("ETH message signature");
            let response = sign_message_with_workflow(&mut workflow, request).await?;
            let normalized = normalize_message_signature(&response)?;
            print_message_signature_response(
                &response.address,
                &normalized.value,
                &response.signature,
            );
        }
        EthSignRequest::TypedData(request) => {
            info!(
                "sign-message command started: chain=ethereum type=eip712 path='{}' scan_timeout_secs={} thp_timeout_secs={}",
                path, args.timeout_secs, args.thp_timeout_secs
            );
            print_requesting("ETH typed-data signature");
            let response = sign_typed_data_with_workflow(&mut workflow, request).await?;
            let normalized = normalize_typed_data_signature(&response)?;
            print_message_signature_response(&response.address, &normalized, &response.signature);
        }
    }

    Ok(())
}

async fn run_btc(args: SignMessageBtcArgs, skip_pairing: bool) -> Result<()> {
    let path = args
        .path
        .as_deref()
        .unwrap_or(DEFAULT_BITCOIN_BIP32_PATH)
        .to_string();
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

    let mut workflow = connect_ready_command_workflow(&args, skip_pairing, "sign-message").await?;

    print_requesting("BTC message signature");
    let response = sign_message_with_workflow(&mut workflow, request).await?;
    let normalized = normalize_message_signature(&response)?;
    print_message_signature_response(&response.address, &normalized.value, &response.signature);
    Ok(())
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
        canned_eth_typed_data_sign_response, ready_workflow_with_mock,
    };
    use hw_wallet::eip712::build_sign_typed_data_request;
    use trezor_connect::thp::Chain as ThpChain;

    #[tokio::test]
    async fn sign_message_eth_flow_uses_ethereum_chain() {
        let backend = MockBackend::paired_with_session_retry(b"msg-eth-test")
            .with_sign_message_response(canned_eth_message_sign_response());
        let mut workflow = ready_workflow_with_mock(backend).await;

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
        let mut workflow = ready_workflow_with_mock(backend).await;

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
        let mut workflow = ready_workflow_with_mock(backend).await;

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
