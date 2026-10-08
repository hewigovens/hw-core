use std::collections::HashMap;

use hw_chain::Chain;

use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{BitcoinTxRequestType, DecodedBitcoinTxRequest, EncodedMessage, TxAck};
use crate::thp::types::{BtcOrigTx, BtcRefTx, BtcSignTx, SignTxResponse};

#[derive(Debug)]
pub(in crate::ble) enum BitcoinTxRequestHandling {
    Ack(EncodedMessage),
    Finished,
    Continue,
}

/// Answers the firmware's `TxRequest`s for one transaction and collects the signatures it returns.
pub(in crate::ble) struct BitcoinTxSigner<'a> {
    tx: &'a BtcSignTx,
    ref_txs: HashMap<&'a [u8], &'a BtcRefTx>,
    orig_txs: HashMap<&'a [u8], &'a BtcOrigTx>,
    signatures: Vec<Vec<u8>>,
    last_signature: Option<Vec<u8>>,
}

impl<'a> BitcoinTxSigner<'a> {
    pub(in crate::ble) fn new(tx: &'a BtcSignTx) -> Self {
        Self {
            tx,
            ref_txs: tx
                .ref_txs
                .iter()
                .map(|tx| (tx.hash.as_slice(), tx))
                .collect(),
            orig_txs: tx
                .orig_txs
                .iter()
                .map(|tx| (tx.hash.as_slice(), tx))
                .collect(),
            signatures: Vec::new(),
            last_signature: None,
        }
    }

    /// Records any signature the request carries, then builds the reply it asks for.
    pub(in crate::ble) fn handle(
        &mut self,
        request: &DecodedBitcoinTxRequest,
    ) -> BackendResult<BitcoinTxRequestHandling> {
        if let Some(signature) = request.signature.as_ref() {
            self.last_signature = Some(signature.clone());
            if let Some(index) = request.signature_index {
                self.record_signature(index, signature)?;
            }
        }
        self.reply(request)
    }

    pub(in crate::ble) fn into_response(self) -> SignTxResponse {
        // Legacy fallback: prefer last indexed signature for 'r'.
        let r = self
            .signatures
            .last()
            .cloned()
            .or(self.last_signature)
            .unwrap_or_default();
        SignTxResponse {
            chain: Chain::Bitcoin,
            v: 0,
            r,
            s: Vec::new(),
            signatures: self.signatures,
        }
    }

    fn record_signature(&mut self, signature_index: u32, signature: &[u8]) -> BackendResult<()> {
        let input_count = self.tx.inputs.len();
        let invalid_index = || {
            BackendError::Device(format!(
                "device returned Bitcoin signature index {signature_index} for input count {input_count}"
            ))
        };
        let index = usize::try_from(signature_index).map_err(|_| invalid_index())?;
        if index >= input_count {
            return Err(invalid_index());
        }
        let required_len = index.checked_add(1).ok_or_else(invalid_index)?;
        if self.signatures.len() < required_len {
            self.signatures.resize(required_len, Vec::new());
        }
        self.signatures[index] = signature.to_vec();
        Ok(())
    }

    fn reply(&self, request: &DecodedBitcoinTxRequest) -> BackendResult<BitcoinTxRequestHandling> {
        let btc = self.tx;
        let ack = match request.request_type {
            Some(BitcoinTxRequestType::TxInput) => {
                let index = request.required_index("TxInput")?;
                if let Some(ref_tx_hash) = request.tx_hash.as_ref() {
                    let ref_tx = self.ref_tx(ref_tx_hash, "TxInput")?;
                    let input = ref_tx.inputs.get(index).ok_or_else(|| {
                        BackendError::Transport(format!(
                            "TxInput request index {} out of bounds for previous transaction {} (inputs={})",
                            index,
                            hex::encode(ref_tx_hash),
                            ref_tx.inputs.len()
                        ))
                    })?;
                    input.tx_ack()
                } else {
                    let input = btc.inputs.get(index).ok_or_else(|| {
                        BackendError::Transport(format!(
                            "TxInput request index {} out of bounds (inputs={})",
                            index,
                            btc.inputs.len()
                        ))
                    })?;
                    input.tx_ack()
                }
            }
            Some(BitcoinTxRequestType::TxOutput) => {
                let index = request.required_index("TxOutput")?;
                if let Some(ref_tx_hash) = request.tx_hash.as_ref() {
                    let ref_tx = self.ref_tx(ref_tx_hash, "TxOutput")?;
                    let output = ref_tx.bin_outputs.get(index).ok_or_else(|| {
                        BackendError::Transport(format!(
                            "TxOutput request index {} out of bounds for previous transaction {} (outputs={})",
                            index,
                            hex::encode(ref_tx_hash),
                            ref_tx.bin_outputs.len()
                        ))
                    })?;
                    output.tx_ack()
                } else {
                    let output = btc.outputs.get(index).ok_or_else(|| {
                        BackendError::Transport(format!(
                            "TxOutput request index {} out of bounds (outputs={})",
                            index,
                            btc.outputs.len()
                        ))
                    })?;
                    output.tx_ack()
                }
            }
            Some(BitcoinTxRequestType::TxMeta) => {
                if let Some(ref_tx_hash) = request.tx_hash.as_ref() {
                    if let Some(orig_tx) = self.orig_txs.get(ref_tx_hash.as_slice()).copied() {
                        orig_tx.tx_ack()
                    } else {
                        self.ref_tx(ref_tx_hash, "TxMeta")?.tx_ack()
                    }
                } else {
                    btc.tx_ack()
                }
            }
            Some(BitcoinTxRequestType::TxExtraData) => {
                let ref_tx_hash = request.tx_hash.as_ref().ok_or_else(|| {
                    BackendError::Transport(
                        "TxExtraData request missing tx_hash for previous transaction".into(),
                    )
                })?;
                let extra_data_len = request.extra_data_len.ok_or_else(|| {
                    BackendError::Transport("TxExtraData request missing extra_data_len".into())
                })? as usize;
                let extra_data_offset = request.extra_data_offset.ok_or_else(|| {
                    BackendError::Transport("TxExtraData request missing extra_data_offset".into())
                })? as usize;
                let extra_data =
                    if let Some(orig_tx) = self.orig_txs.get(ref_tx_hash.as_slice()).copied() {
                        orig_tx.extra_data.as_deref()
                    } else {
                        self.ref_tx(ref_tx_hash, "TxExtraData")?
                            .extra_data
                            .as_deref()
                    }
                    .ok_or_else(|| {
                        BackendError::Transport(format!(
                            "TxExtraData requested for transaction {} without extra_data",
                            hex::encode(ref_tx_hash)
                        ))
                    })?;
                let end = extra_data_offset
                    .checked_add(extra_data_len)
                    .ok_or_else(|| {
                        BackendError::Transport("TxExtraData request range overflows usize".into())
                    })?;
                if end > extra_data.len() {
                    return Err(BackendError::Transport(format!(
                        "TxExtraData request range [{}, {}) out of bounds for previous transaction {} (extra_data_len={})",
                        extra_data_offset,
                        end,
                        hex::encode(ref_tx_hash),
                        extra_data.len()
                    )));
                }
                extra_data[extra_data_offset..end].tx_ack()
            }
            Some(BitcoinTxRequestType::TxFinished) => {
                return Ok(BitcoinTxRequestHandling::Finished);
            }
            Some(BitcoinTxRequestType::TxOrigInput) => {
                let orig_tx_hash = request.tx_hash.as_ref().ok_or_else(|| {
                    BackendError::Transport("TxOrigInput request missing tx_hash".into())
                })?;
                let orig_tx = self.orig_tx(orig_tx_hash, "TxOrigInput")?;
                let index = request.required_index("TxOrigInput")?;
                let input = orig_tx.inputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOrigInput request index {} out of bounds for original transaction {} (inputs={})",
                        index,
                        hex::encode(orig_tx_hash),
                        orig_tx.inputs.len()
                    ))
                })?;
                input.tx_ack()
            }
            Some(BitcoinTxRequestType::TxOrigOutput) => {
                let orig_tx_hash = request.tx_hash.as_ref().ok_or_else(|| {
                    BackendError::Transport("TxOrigOutput request missing tx_hash".into())
                })?;
                let orig_tx = self.orig_tx(orig_tx_hash, "TxOrigOutput")?;
                let index = request.required_index("TxOrigOutput")?;
                let output = orig_tx.outputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOrigOutput request index {} out of bounds for original transaction {} (outputs={})",
                        index,
                        hex::encode(orig_tx_hash),
                        orig_tx.outputs.len()
                    ))
                })?;
                output.tx_ack()
            }
            Some(BitcoinTxRequestType::TxPaymentReq) => {
                let index = request.required_index("TxPaymentReq")?;
                let payment_req = btc.payment_reqs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxPaymentReq request index {} out of bounds (payment_reqs={})",
                        index,
                        btc.payment_reqs.len()
                    ))
                })?;
                payment_req.tx_ack()
            }
            None => return Ok(BitcoinTxRequestHandling::Continue),
        };
        Ok(BitcoinTxRequestHandling::Ack(ack))
    }

    fn ref_tx(&self, tx_hash: &[u8], request_name: &str) -> BackendResult<&'a BtcRefTx> {
        self.ref_txs.get(tx_hash).copied().ok_or_else(|| {
            BackendError::Transport(format!(
                "{request_name} request references unknown previous transaction hash {}",
                hex::encode(tx_hash)
            ))
        })
    }

    fn orig_tx(&self, tx_hash: &[u8], request_name: &str) -> BackendResult<&'a BtcOrigTx> {
        self.orig_txs.get(tx_hash).copied().ok_or_else(|| {
            BackendError::Transport(format!(
                "{request_name} request references unknown original transaction hash {}",
                hex::encode(tx_hash)
            ))
        })
    }
}

impl DecodedBitcoinTxRequest {
    fn required_index(&self, request_name: &str) -> BackendResult<usize> {
        self.request_index
            .map(|value| value as usize)
            .ok_or_else(|| {
                BackendError::Transport(format!("{request_name} request missing request_index"))
            })
    }
}
