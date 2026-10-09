use serde::Deserialize;
use trezor_connect::thp::{BtcRefTx, BtcRefTxInput, BtcRefTxOutput};

use super::inputs::default_sequence;
use super::sats::parse_sats;
use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_hash32};

#[derive(Debug, Deserialize)]
pub struct TxInputRefTx {
    pub hash: String,
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<TxInputRefTxInput>,
    pub bin_outputs: Vec<TxInputRefTxOutput>,
    pub extra_data: Option<String>,
    pub timestamp: Option<u32>,
    pub version_group_id: Option<u32>,
    pub expiry: Option<u32>,
    pub branch_id: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TxInputRefTxInput {
    pub prev_hash: String,
    pub prev_index: u32,
    pub script_sig: String,
    #[serde(default = "default_sequence")]
    pub sequence: u32,
}

#[derive(Debug, Deserialize)]
pub struct TxInputRefTxOutput {
    pub amount: String,
    pub script_pubkey: String,
}

impl TryFrom<TxInputRefTx> for BtcRefTx {
    type Error = WalletError;

    fn try_from(tx: TxInputRefTx) -> WalletResult<Self> {
        Ok(Self {
            hash: decode_hash32("ref_txs.hash", &tx.hash)?,
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx
                .inputs
                .into_iter()
                .map(BtcRefTxInput::try_from)
                .collect::<WalletResult<_>>()?,
            bin_outputs: tx
                .bin_outputs
                .into_iter()
                .map(BtcRefTxOutput::try_from)
                .collect::<WalletResult<_>>()?,
            extra_data: tx.extra_data.as_deref().map(decode).transpose()?,
            timestamp: tx.timestamp,
            version_group_id: tx.version_group_id,
            expiry: tx.expiry,
            branch_id: tx.branch_id,
        })
    }
}

impl TryFrom<TxInputRefTxInput> for BtcRefTxInput {
    type Error = WalletError;

    fn try_from(input: TxInputRefTxInput) -> WalletResult<Self> {
        Ok(Self {
            prev_hash: decode_hash32("ref_txs.inputs.prev_hash", &input.prev_hash)?,
            prev_index: input.prev_index,
            script_sig: decode(&input.script_sig)?,
            sequence: input.sequence,
        })
    }
}

impl TryFrom<TxInputRefTxOutput> for BtcRefTxOutput {
    type Error = WalletError;

    fn try_from(output: TxInputRefTxOutput) -> WalletResult<Self> {
        Ok(Self {
            amount: parse_sats(&output.amount)?,
            script_pubkey: decode(&output.script_pubkey)?,
        })
    }
}
