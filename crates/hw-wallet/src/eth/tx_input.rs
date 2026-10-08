use serde::Deserialize;
use trezor_connect::thp::{EthAccessListEntry, EthSignTx};

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

impl TxInput {
    pub fn from_json(json: &str) -> WalletResult<Self> {
        serde_json::from_str(json)
            .map_err(|err| WalletError::Signing(format!("invalid tx JSON: {err}")))
    }

    pub fn into_sign_tx(self, path: Vec<u32>) -> WalletResult<EthSignTx> {
        let nonce = decode_quantity(&self.nonce)?;
        let max_fee_per_gas = decode_quantity(&self.max_fee_per_gas)?;
        let max_priority_fee = decode_quantity(&self.max_priority_fee)?;
        let gas_limit = decode_quantity(&self.gas_limit)?;
        let value = decode_quantity(&self.value)?;
        let data = decode(&self.data)?;
        let access_list = self
            .access_list
            .into_iter()
            .map(EthAccessListEntry::try_from)
            .collect::<WalletResult<_>>()?;

        Ok(EthSignTx::new(path, self.chain_id)
            .with_nonce(nonce)
            .with_max_fee_per_gas(max_fee_per_gas)
            .with_max_priority_fee(max_priority_fee)
            .with_gas_limit(gas_limit)
            .with_to(self.to)
            .with_value(value)
            .with_data(data)
            .with_access_list(access_list))
    }
}

impl TryFrom<TxAccessListInput> for EthAccessListEntry {
    type Error = WalletError;

    fn try_from(entry: TxAccessListInput) -> WalletResult<Self> {
        Ok(Self {
            storage_keys: entry
                .storage_keys
                .iter()
                .map(|key| decode(key))
                .collect::<WalletResult<_>>()?,
            address: entry.address,
        })
    }
}
