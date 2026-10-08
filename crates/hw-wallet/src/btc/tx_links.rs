use std::collections::HashMap;

use trezor_connect::thp::{BtcOrigTx, BtcSignTx};

use crate::error::{WalletError, WalletResult};

/// Checks that every input and output resolves against the referenced and original transactions.
pub(super) trait TxLinks {
    fn validate_ref_txs(&self) -> WalletResult<()>;
    fn validate_orig_tx_links(&self) -> WalletResult<()>;
}

impl TxLinks for BtcSignTx {
    fn validate_ref_txs(&self) -> WalletResult<()> {
        let ref_txs = index_by_hash(&self.ref_txs, |tx| &tx.hash, "ref_txs")?;
        for (input_index, input) in self.inputs.iter().enumerate() {
            let Some(ref_tx) = ref_txs.get(input.prev_hash.as_slice()) else {
                return Err(WalletError::Signing(format!(
                    "ref_txs must include transaction {} referenced by input {}",
                    hex::encode(&input.prev_hash),
                    input_index
                )));
            };
            if input.prev_index as usize >= ref_tx.bin_outputs.len() {
                return Err(WalletError::Signing(format!(
                    "input {input_index} prev_index {} out of bounds for ref_txs hash {} (outputs={})",
                    input.prev_index,
                    hex::encode(&input.prev_hash),
                    ref_tx.bin_outputs.len()
                )));
            }
        }
        Ok(())
    }

    fn validate_orig_tx_links(&self) -> WalletResult<()> {
        let orig_txs = index_by_hash(&self.orig_txs, |tx| &tx.hash, "original transaction")?;
        for (index, input) in self.inputs.iter().enumerate() {
            check_orig_link(
                &orig_txs,
                "inputs",
                index,
                &input.orig_hash,
                input.orig_index,
                |tx| tx.inputs.len(),
            )?;
        }
        for (index, output) in self.outputs.iter().enumerate() {
            check_orig_link(
                &orig_txs,
                "outputs",
                index,
                &output.orig_hash,
                output.orig_index,
                |tx| tx.outputs.len(),
            )?;
        }
        Ok(())
    }
}

fn index_by_hash<'a, T>(
    txs: &'a [T],
    hash: impl Fn(&'a T) -> &'a Vec<u8>,
    label: &str,
) -> WalletResult<HashMap<&'a [u8], &'a T>> {
    let mut by_hash = HashMap::with_capacity(txs.len());
    for tx in txs {
        let hash = hash(tx);
        if by_hash.insert(hash.as_slice(), tx).is_some() {
            return Err(WalletError::Signing(format!(
                "duplicate {label} hash {}",
                hex::encode(hash)
            )));
        }
    }
    Ok(by_hash)
}

fn check_orig_link(
    orig_txs: &HashMap<&[u8], &BtcOrigTx>,
    kind: &str,
    index: usize,
    orig_hash: &Option<Vec<u8>>,
    orig_index: Option<u32>,
    linked_len: impl Fn(&BtcOrigTx) -> usize,
) -> WalletResult<()> {
    match (orig_hash, orig_index) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(WalletError::Signing(format!(
            "{kind}[{index}] must specify both orig_hash and orig_index"
        ))),
        (Some(orig_hash), Some(orig_index)) => {
            let orig_tx = orig_txs.get(orig_hash.as_slice()).ok_or_else(|| {
                WalletError::Signing(format!(
                    "missing original transaction {} for {kind}[{index}]",
                    hex::encode(orig_hash)
                ))
            })?;
            if usize::try_from(orig_index)
                .ok()
                .is_none_or(|idx| idx >= linked_len(orig_tx))
            {
                return Err(WalletError::Signing(format!(
                    "orig_index {orig_index} out of bounds for {kind}[{index}]"
                )));
            }
            Ok(())
        }
    }
}
