use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::btc::{
    build_sign_tx_request as build_btc_sign_tx_request, parse_tx_json as parse_btc_tx_json,
};
use hw_wallet::eth::{TxAccessListInput, TxInput, build_sign_tx_request};
use hw_wallet::hex::decode as decode_hex;
use hw_wallet::message::build_sign_message_request;
use hw_wallet::message_signing::{build_eth_eip191_request, build_eth_eip712_request};
use trezor_connect::thp::{
    GetAddressRequest as ThpGetAddressRequest, SignMessageRequest as ThpSignMessageRequest,
};

use crate::ble::MIN_SOLANA_SERIALIZED_TX_BYTES;
use crate::errors::HWCoreError;
use crate::types::{
    AccessListEntry, GetAddressRequest, SignMessageRequest, SignTxRequest, SignTypedDataRequest,
};

pub(crate) fn map_get_address_request(
    request: GetAddressRequest,
) -> Result<ThpGetAddressRequest, HWCoreError> {
    let path = parse_request_path(&request.path)?;
    Ok(ThpGetAddressRequest {
        chain: request.chain,
        path,
        show_display: request.show_on_device,
        chunkify: request.chunkify,
        encoded_network: None,
        include_public_key: request.include_public_key,
    })
}

pub(crate) fn map_sign_tx_request(
    request: SignTxRequest,
) -> Result<trezor_connect::thp::SignTxRequest, HWCoreError> {
    match request.chain {
        crate::types::Chain::Ethereum => {
            let path = parse_request_path(&request.path)?;
            let tx = TxInput {
                to: request.to,
                value: request.value,
                nonce: request.nonce,
                gas_limit: request.gas_limit,
                chain_id: request.chain_id,
                data: request.data,
                max_fee_per_gas: request.max_fee_per_gas,
                max_priority_fee: request.max_priority_fee,
                access_list: request
                    .access_list
                    .into_iter()
                    .map(|entry: AccessListEntry| TxAccessListInput {
                        address: entry.address,
                        storage_keys: entry.storage_keys,
                    })
                    .collect(),
            };

            let mut sign_request = build_sign_tx_request(path, tx).map_err(HWCoreError::from)?;
            sign_request.chunkify = request.chunkify;
            Ok(sign_request)
        }
        crate::types::Chain::Solana => {
            let path = parse_request_path(&request.path)?;
            let serialized_tx = decode_hex(&request.data).map_err(HWCoreError::from)?;
            if serialized_tx.len() < MIN_SOLANA_SERIALIZED_TX_BYTES {
                return Err(HWCoreError::Validation(format!(
                    "solana serialized tx is too short ({} bytes); provide full serialized transaction bytes",
                    serialized_tx.len()
                )));
            }
            Ok(trezor_connect::thp::SignTxRequest::solana(
                path,
                serialized_tx,
            ))
        }
        crate::types::Chain::Bitcoin => {
            let tx = parse_btc_tx_json(&request.data).map_err(HWCoreError::from)?;
            build_btc_sign_tx_request(tx).map_err(HWCoreError::from)
        }
    }
}

pub(crate) fn map_sign_message_request(
    request: SignMessageRequest,
) -> Result<ThpSignMessageRequest, HWCoreError> {
    let path = parse_request_path(&request.path)?;
    match request.chain {
        crate::types::Chain::Ethereum => {
            build_eth_eip191_request(path, &request.message, request.is_hex, request.chunkify)
                .map_err(HWCoreError::from)
        }
        _ => build_sign_message_request(
            request.chain,
            path,
            &request.message,
            request.is_hex,
            request.chunkify,
        )
        .map_err(HWCoreError::from),
    }
}

pub(crate) fn map_sign_typed_data_request(
    request: SignTypedDataRequest,
) -> Result<trezor_connect::thp::SignTypedDataRequest, HWCoreError> {
    if request.chain != crate::types::Chain::Ethereum {
        return Err(HWCoreError::Validation(
            "typed-data signing currently supports Ethereum only".to_string(),
        ));
    }

    let path = parse_request_path(&request.path)?;
    let domain_separator_hash = non_empty_string(request.domain_separator_hash);
    let message_hash = optional_non_empty_string(request.message_hash);

    build_eth_eip712_request(
        path,
        request.data_json.as_deref(),
        domain_separator_hash.as_deref(),
        message_hash.as_deref(),
        request.metamask_v4_compat,
    )
    .map_err(HWCoreError::from)
}

fn parse_request_path(path: &str) -> Result<Vec<u32>, HWCoreError> {
    parse_bip32_path(path).map_err(HWCoreError::from)
}

fn non_empty_string(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn optional_non_empty_string(value: Option<String>) -> Option<String> {
    value.and_then(non_empty_string)
}
