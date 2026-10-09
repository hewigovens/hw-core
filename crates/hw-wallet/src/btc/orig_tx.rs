use serde::Deserialize;
use trezor_connect::thp::BtcOrigTx;

use super::inputs::TxInputInput;
use super::outputs::TxInputOutput;
use super::owner::TxOwner;
use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_hash32};

#[derive(Debug, Deserialize)]
pub struct TxInputOrigTx {
    pub hash: String,
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<TxInputInput>,
    pub outputs: Vec<TxInputOutput>,
    pub extra_data: Option<String>,
    pub timestamp: Option<u32>,
    pub version_group_id: Option<u32>,
    pub expiry: Option<u32>,
    pub branch_id: Option<u32>,
}

impl TryFrom<TxInputOrigTx> for BtcOrigTx {
    type Error = WalletError;

    fn try_from(tx: TxInputOrigTx) -> WalletResult<Self> {
        Ok(Self {
            hash: decode_hash32("orig_txs.hash", &tx.hash)?,
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx
                .inputs
                .into_iter()
                .map(|input| input.into_sign_input(TxOwner::Original))
                .collect::<WalletResult<_>>()?,
            outputs: tx
                .outputs
                .into_iter()
                .map(|output| output.into_sign_output(TxOwner::Original))
                .collect::<WalletResult<_>>()?,
            extra_data: tx.extra_data.as_deref().map(decode).transpose()?,
            timestamp: tx.timestamp,
            version_group_id: tx.version_group_id,
            expiry: tx.expiry,
            branch_id: tx.branch_id,
        })
    }
}
