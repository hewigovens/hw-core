use serde::Deserialize;
use trezor_connect::thp::{BtcOrigTx, BtcPaymentRequest, BtcRefTx, BtcSignTx};

use super::inputs::TxInputInput;
use super::orig_tx::TxInputOrigTx;
use super::outputs::TxInputOutput;
use super::owner::TxOwner;
use super::payment_request::TxInputPaymentRequest;
use super::ref_tx::TxInputRefTx;
use super::tx_links::TxLinks;
use crate::error::{WalletError, WalletResult};

#[derive(Debug, Deserialize)]
pub struct TxInput {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub lock_time: u32,
    #[serde(default)]
    pub chunkify: bool,
    pub inputs: Vec<TxInputInput>,
    pub outputs: Vec<TxInputOutput>,
    #[serde(default)]
    pub ref_txs: Vec<TxInputRefTx>,
    #[serde(default)]
    pub orig_txs: Vec<TxInputOrigTx>,
    #[serde(default)]
    pub payment_reqs: Vec<TxInputPaymentRequest>,
}

fn default_version() -> u32 {
    2
}

impl TxInput {
    pub fn from_json(json: &str) -> WalletResult<Self> {
        serde_json::from_str(json)
            .map_err(|err| WalletError::Signing(format!("invalid bitcoin tx JSON: {err}")))
    }
}

impl TryFrom<TxInput> for BtcSignTx {
    type Error = WalletError;

    fn try_from(tx: TxInput) -> WalletResult<Self> {
        if tx.inputs.is_empty() {
            return Err(WalletError::Signing(
                "bitcoin tx must contain at least one input".into(),
            ));
        }
        if tx.outputs.is_empty() {
            return Err(WalletError::Signing(
                "bitcoin tx must contain at least one output".into(),
            ));
        }

        let sign_tx = Self {
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx
                .inputs
                .into_iter()
                .map(|input| input.into_sign_input(TxOwner::Signing))
                .collect::<WalletResult<_>>()?,
            outputs: tx
                .outputs
                .into_iter()
                .map(|output| output.into_sign_output(TxOwner::Signing))
                .collect::<WalletResult<_>>()?,
            ref_txs: tx
                .ref_txs
                .into_iter()
                .map(BtcRefTx::try_from)
                .collect::<WalletResult<_>>()?,
            orig_txs: tx
                .orig_txs
                .into_iter()
                .map(BtcOrigTx::try_from)
                .collect::<WalletResult<_>>()?,
            payment_reqs: tx
                .payment_reqs
                .into_iter()
                .map(BtcPaymentRequest::try_from)
                .collect::<WalletResult<_>>()?,
            chunkify: tx.chunkify,
        };
        sign_tx.validate_ref_txs()?;
        sign_tx.validate_orig_tx_links()?;
        Ok(sign_tx)
    }
}
