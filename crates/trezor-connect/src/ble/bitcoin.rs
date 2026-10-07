use std::collections::HashMap;

use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{
    BitcoinTxRequestType, DecodedBitcoinTxRequest, EncodedMessage, encode_bitcoin_tx_ack_input,
    encode_bitcoin_tx_ack_meta, encode_bitcoin_tx_ack_orig_meta, encode_bitcoin_tx_ack_output,
    encode_bitcoin_tx_ack_payment_request, encode_bitcoin_tx_ack_prev_extra_data,
    encode_bitcoin_tx_ack_prev_input, encode_bitcoin_tx_ack_prev_meta,
    encode_bitcoin_tx_ack_prev_output,
};

#[derive(Debug)]
pub(super) enum BitcoinTxRequestHandling {
    Ack(EncodedMessage),
    Finished,
    Continue,
}

fn request_index(tx_request: &DecodedBitcoinTxRequest, request_name: &str) -> BackendResult<usize> {
    tx_request
        .request_index
        .map(|value| value as usize)
        .ok_or_else(|| {
            BackendError::Transport(format!("{request_name} request missing request_index"))
        })
}

pub(super) fn build_ref_txs_index(
    btc: &crate::thp::types::BtcSignTx,
) -> HashMap<&[u8], &crate::thp::types::BtcRefTx> {
    btc.ref_txs
        .iter()
        .map(|tx| (tx.hash.as_slice(), tx))
        .collect()
}

pub(super) fn build_orig_txs_index(
    btc: &crate::thp::types::BtcSignTx,
) -> HashMap<&[u8], &crate::thp::types::BtcOrigTx> {
    btc.orig_txs
        .iter()
        .map(|tx| (tx.hash.as_slice(), tx))
        .collect()
}

fn find_ref_tx<'a>(
    ref_txs_by_hash: &'a HashMap<&'a [u8], &'a crate::thp::types::BtcRefTx>,
    tx_hash: &[u8],
    request_name: &str,
) -> BackendResult<&'a crate::thp::types::BtcRefTx> {
    ref_txs_by_hash.get(tx_hash).copied().ok_or_else(|| {
        BackendError::Transport(format!(
            "{request_name} request references unknown previous transaction hash {}",
            hex::encode(tx_hash)
        ))
    })
}

fn find_orig_tx<'a>(
    orig_txs_by_hash: &'a HashMap<&'a [u8], &'a crate::thp::types::BtcOrigTx>,
    tx_hash: &[u8],
    request_name: &str,
) -> BackendResult<&'a crate::thp::types::BtcOrigTx> {
    orig_txs_by_hash.get(tx_hash).copied().ok_or_else(|| {
        BackendError::Transport(format!(
            "{request_name} request references unknown original transaction hash {}",
            hex::encode(tx_hash)
        ))
    })
}

pub(super) fn handle_bitcoin_tx_request(
    btc: &crate::thp::types::BtcSignTx,
    ref_txs_by_hash: &HashMap<&[u8], &crate::thp::types::BtcRefTx>,
    orig_txs_by_hash: &HashMap<&[u8], &crate::thp::types::BtcOrigTx>,
    tx_request: &DecodedBitcoinTxRequest,
) -> BackendResult<BitcoinTxRequestHandling> {
    match tx_request.request_type {
        Some(BitcoinTxRequestType::TxInput) => {
            let index = request_index(tx_request, "TxInput")?;
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxInput")?;
                let input = ref_tx.inputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxInput request index {} out of bounds for previous transaction {} (inputs={})",
                        index,
                        hex::encode(ref_tx_hash),
                        ref_tx.inputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_prev_input(input)
            } else {
                let input = btc.inputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxInput request index {} out of bounds (inputs={})",
                        index,
                        btc.inputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_input(input)
            }
            .map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxOutput) => {
            let index = request_index(tx_request, "TxOutput")?;
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxOutput")?;
                let output = ref_tx.bin_outputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOutput request index {} out of bounds for previous transaction {} (outputs={})",
                        index,
                        hex::encode(ref_tx_hash),
                        ref_tx.bin_outputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_prev_output(output)
            } else {
                let output = btc.outputs.get(index).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "TxOutput request index {} out of bounds (outputs={})",
                        index,
                        btc.outputs.len()
                    ))
                })?;
                encode_bitcoin_tx_ack_output(output)
            }
            .map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxMeta) => {
            let ack = if let Some(ref_tx_hash) = tx_request.tx_hash.as_ref() {
                if let Some(orig_tx) = orig_txs_by_hash.get(ref_tx_hash.as_slice()).copied() {
                    encode_bitcoin_tx_ack_orig_meta(orig_tx)
                } else {
                    let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxMeta")?;
                    encode_bitcoin_tx_ack_prev_meta(ref_tx)
                }
            } else {
                encode_bitcoin_tx_ack_meta(
                    btc.version,
                    btc.lock_time,
                    btc.inputs.len(),
                    btc.outputs.len(),
                )
            }
            .map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxExtraData) => {
            let ref_tx_hash = tx_request.tx_hash.as_ref().ok_or_else(|| {
                BackendError::Transport(
                    "TxExtraData request missing tx_hash for previous transaction".into(),
                )
            })?;
            let extra_data_len = tx_request.extra_data_len.ok_or_else(|| {
                BackendError::Transport("TxExtraData request missing extra_data_len".into())
            })? as usize;
            let extra_data_offset = tx_request.extra_data_offset.ok_or_else(|| {
                BackendError::Transport("TxExtraData request missing extra_data_offset".into())
            })? as usize;
            let extra_data =
                if let Some(orig_tx) = orig_txs_by_hash.get(ref_tx_hash.as_slice()).copied() {
                    orig_tx.extra_data.as_deref()
                } else {
                    let ref_tx = find_ref_tx(ref_txs_by_hash, ref_tx_hash, "TxExtraData")?;
                    ref_tx.extra_data.as_deref()
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
            let ack = encode_bitcoin_tx_ack_prev_extra_data(&extra_data[extra_data_offset..end])
                .map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxFinished) => Ok(BitcoinTxRequestHandling::Finished),
        Some(BitcoinTxRequestType::TxOrigInput) => {
            let orig_tx_hash = tx_request.tx_hash.as_ref().ok_or_else(|| {
                BackendError::Transport("TxOrigInput request missing tx_hash".into())
            })?;
            let orig_tx = find_orig_tx(orig_txs_by_hash, orig_tx_hash, "TxOrigInput")?;
            let index = request_index(tx_request, "TxOrigInput")?;
            let input = orig_tx.inputs.get(index).ok_or_else(|| {
                BackendError::Transport(format!(
                    "TxOrigInput request index {} out of bounds for original transaction {} (inputs={})",
                    index,
                    hex::encode(orig_tx_hash),
                    orig_tx.inputs.len()
                ))
            })?;
            let ack = encode_bitcoin_tx_ack_input(input).map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxOrigOutput) => {
            let orig_tx_hash = tx_request.tx_hash.as_ref().ok_or_else(|| {
                BackendError::Transport("TxOrigOutput request missing tx_hash".into())
            })?;
            let orig_tx = find_orig_tx(orig_txs_by_hash, orig_tx_hash, "TxOrigOutput")?;
            let index = request_index(tx_request, "TxOrigOutput")?;
            let output = orig_tx.outputs.get(index).ok_or_else(|| {
                BackendError::Transport(format!(
                    "TxOrigOutput request index {} out of bounds for original transaction {} (outputs={})",
                    index,
                    hex::encode(orig_tx_hash),
                    orig_tx.outputs.len()
                ))
            })?;
            let ack = encode_bitcoin_tx_ack_output(output).map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        Some(BitcoinTxRequestType::TxPaymentReq) => {
            let index = request_index(tx_request, "TxPaymentReq")?;
            let pr = btc.payment_reqs.get(index).ok_or_else(|| {
                BackendError::Transport(format!(
                    "TxPaymentReq request index {} out of bounds (payment_reqs={})",
                    index,
                    btc.payment_reqs.len()
                ))
            })?;
            let ack = encode_bitcoin_tx_ack_payment_request(pr).map_err(super::mapping_error)?;
            Ok(BitcoinTxRequestHandling::Ack(ack))
        }
        None => Ok(BitcoinTxRequestHandling::Continue),
    }
}
