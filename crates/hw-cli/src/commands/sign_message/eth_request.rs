use anyhow::Result;
use trezor_connect::thp::{SignMessageRequest, SignTypedDataRequest};

use crate::cli::{EthSignMessageType, SignMessageEthArgs};
use crate::commands::common::read_text_file;

use hw_wallet::message_signing::{build_eth_eip191_request, build_eth_eip712_json_request};

#[derive(Debug)]
pub(super) enum EthSignRequest {
    Message(SignMessageRequest),
    TypedData(SignTypedDataRequest),
}

pub(super) fn build_eth_sign_request_from_args(
    args: &SignMessageEthArgs,
    path: Vec<u32>,
) -> Result<EthSignRequest> {
    match args.message_type {
        EthSignMessageType::Eip191 => {
            if args.data_file.is_some() {
                anyhow::bail!("ETH EIP-191 signing cannot be combined with EIP-712 fields");
            }

            let message = args
                .message
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("ETH EIP-191 signing requires `message`"))?;

            build_eth_eip191_request(path, message, args.hex, args.chunkify)
                .map(EthSignRequest::Message)
                .map_err(Into::into)
        }
        EthSignMessageType::Eip712 => {
            if args.message.is_some() {
                anyhow::bail!("ETH EIP-712 signing cannot be combined with `message`");
            }
            if args.hex || args.chunkify {
                anyhow::bail!("`hex` and `chunkify` are only valid for ETH EIP-191 signing");
            }

            let data_file = args
                .data_file
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--data-file is required for --type eip712"))?;
            let data_json = read_text_file(data_file, "typed-data file")?;

            build_eth_eip712_json_request(path, &data_json, args.metamask_v4_compat)
                .map(EthSignRequest::TypedData)
                .map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    #[test]
    fn build_eth_sign_request_from_args_rejects_mixed_eip712_inputs() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/data/ethereum/eip712_invalid_missing_domain_type.json");
        let err = build_eth_sign_request_from_args(
            &SignMessageEthArgs {
                path: Some("m/44'/60'/0'/0/0".into()),
                message: Some("hello".into()),
                message_type: EthSignMessageType::Eip712,
                hex: false,
                chunkify: false,
                data_file: Some(fixture),
                metamask_v4_compat: true,
                timeout_secs: 60,
                thp_timeout_secs: 60,
                device_id: None,
                storage_path: None,
                host_name: None,
                app_name: "hw-core/cli".into(),
            },
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
        )
        .expect_err("mixed EIP-712 inputs should fail");

        assert!(
            err.to_string()
                .contains("cannot be combined with `message`")
        );
    }

    #[test]
    fn build_eth_sign_request_from_args_rejects_missing_eip712_payload() {
        let err = build_eth_sign_request_from_args(
            &SignMessageEthArgs {
                path: Some("m/44'/60'/0'/0/0".into()),
                message: None,
                message_type: EthSignMessageType::Eip712,
                hex: false,
                chunkify: false,
                data_file: None,
                metamask_v4_compat: true,
                timeout_secs: 60,
                thp_timeout_secs: 60,
                device_id: None,
                storage_path: None,
                host_name: None,
                app_name: "hw-core/cli".into(),
            },
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
        )
        .expect_err("missing EIP-712 payload should fail");

        assert!(
            err.to_string()
                .contains("--data-file is required for --type eip712")
        );
    }
}
