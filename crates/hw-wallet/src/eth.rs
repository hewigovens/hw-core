use serde::Deserialize;
use trezor_connect::thp::{EthAccessListEntry, SignTxRequest};

use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_quantity};

#[derive(Debug, Deserialize)]
pub struct TxInput {
    pub to: String,
    #[serde(default = "default_hex_zero")]
    pub value: String,
    #[serde(default = "default_hex_zero")]
    pub nonce: String,
    #[serde(default = "default_hex_zero")]
    pub gas_limit: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    #[serde(default = "default_hex_zero")]
    pub data: String,
    #[serde(default = "default_hex_zero")]
    pub max_fee_per_gas: String,
    #[serde(default = "default_hex_zero")]
    pub max_priority_fee: String,
    #[serde(default)]
    pub access_list: Vec<TxAccessListInput>,
}

#[derive(Debug, Deserialize)]
pub struct TxAccessListInput {
    pub address: String,
    #[serde(default)]
    pub storage_keys: Vec<String>,
}

fn default_hex_zero() -> String {
    "0x0".to_string()
}

fn default_chain_id() -> u64 {
    1
}

pub fn parse_tx_json(json: &str) -> WalletResult<TxInput> {
    serde_json::from_str(json)
        .map_err(|err| WalletError::Signing(format!("invalid tx JSON: {err}")))
}

pub fn build_sign_tx_request(path: Vec<u32>, tx: TxInput) -> WalletResult<SignTxRequest> {
    let nonce = decode_quantity(&tx.nonce)?;
    let max_fee_per_gas = decode_quantity(&tx.max_fee_per_gas)?;
    let max_priority_fee = decode_quantity(&tx.max_priority_fee)?;
    let gas_limit = decode_quantity(&tx.gas_limit)?;
    let value = decode_quantity(&tx.value)?;
    let data = decode(&tx.data)?;

    let access_list: Vec<EthAccessListEntry> = tx
        .access_list
        .into_iter()
        .map(|entry| {
            let storage_keys = entry
                .storage_keys
                .iter()
                .map(|key| decode(key))
                .collect::<WalletResult<Vec<_>>>()?;
            Ok(EthAccessListEntry {
                address: entry.address,
                storage_keys,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    Ok(SignTxRequest::ethereum(path, tx.chain_id)
        .with_nonce(nonce)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee(max_priority_fee)
        .with_gas_limit(gas_limit)
        .with_to(tx.to)
        .with_value(value)
        .with_data(data)
        .with_access_list(access_list))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tx_json_minimal() {
        let tx = parse_tx_json(r#"{"to":"0xdead"}"#).unwrap();
        assert_eq!(tx.to, "0xdead");
        assert_eq!(tx.chain_id, 1);
    }

    #[test]
    fn build_sign_tx_request_from_json() {
        let tx = parse_tx_json(
            r#"{
                "to":"0xdead",
                "nonce":"0x1",
                "gas_limit":"0x5208",
                "chain_id":1,
                "max_fee_per_gas":"0x3b9aca00",
                "max_priority_fee":"0x59682f00"
            }"#,
        )
        .unwrap();

        let path = vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
        let request = build_sign_tx_request(path.clone(), tx).unwrap();
        assert_eq!(request.path, path);
        assert_eq!(request.chain_id, 1);
        assert_eq!(request.nonce, vec![1]);
        assert_eq!(request.gas_limit, vec![0x52, 0x08]);
    }
}
