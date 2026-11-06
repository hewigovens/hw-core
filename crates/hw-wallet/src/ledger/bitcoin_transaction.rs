use super::{
    LedgerBitcoinTxResult, bitcoin_account::BitcoinAccount, bitcoin_purpose::BitcoinPurpose,
};
use crate::{WalletError, WalletResult};
use bitcoin::{
    Address, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
    absolute::LockTime,
    hashes::Hash,
    psbt::Psbt,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
    transaction::Version,
};
use ledger_bitcoin_client::{PartialSignature, SignPsbtYieldedObject};
use std::{collections::HashSet, str::FromStr};
use trezor_connect::thp::{BtcInputScriptType, BtcOutputScriptType, BtcRefTx, BtcSignTx};

pub(super) struct BitcoinTransaction {
    pub psbt: Psbt,
    keys: Vec<PublicKey>,
}

impl BitcoinTransaction {
    fn invalid(message: &str) -> WalletError {
        WalletError::Signing(message.into())
    }

    pub fn validate(request: &BtcSignTx) -> WalletResult<()> {
        if request.inputs.is_empty()
            || request.outputs.is_empty()
            || request.inputs.len() > 256
            || request.outputs.len() > 256
        {
            return Err(Self::invalid(
                "Ledger Bitcoin requires 1 to 256 inputs and outputs",
            ));
        }
        if ![1, 2].contains(&request.version)
            || request.chunkify
            || !request.orig_txs.is_empty()
            || !request.payment_reqs.is_empty()
        {
            return Err(Self::invalid(
                "Ledger Bitcoin supports version 1/2 transactions without Trezor replacement, payment-request or display metadata",
            ));
        }
        let mut outpoints = HashSet::new();
        for input in &request.inputs {
            let (purpose, _) = BitcoinAccount::validate_path(&input.path)?;
            if purpose != BitcoinPurpose::Segwit
                || input.path[..3] != request.inputs[0].path[..3]
                || input.script_type != BtcInputScriptType::SpendWitness
                || input.multisig.is_some()
                || input.script_sig.is_some()
                || input.witness.is_some()
                || input.orig_hash.is_some()
                || input.orig_index.is_some()
            {
                return Err(Self::invalid(
                    "Ledger Bitcoin signing currently requires unsigned single-account BIP84 P2WPKH inputs",
                ));
            }
            if !outpoints.insert((input.prev_hash.clone(), input.prev_index)) {
                return Err(Self::invalid("duplicate Bitcoin input"));
            }
        }
        Ok(())
    }

    fn txid(bytes: &[u8]) -> WalletResult<Txid> {
        Txid::from_str(&hex::encode(bytes))
            .map_err(|_| Self::invalid("Bitcoin transaction hash must be 32 bytes"))
    }

    fn reference(reference: &BtcRefTx) -> WalletResult<Transaction> {
        if reference.extra_data.is_some()
            || reference.timestamp.is_some()
            || reference.version_group_id.is_some()
            || reference.expiry.is_some()
            || reference.branch_id.is_some()
        {
            return Err(Self::invalid(
                "Bitcoin reference transaction contains unsupported coin metadata",
            ));
        }
        let transaction = Transaction {
            version: Version(reference.version as i32),
            lock_time: LockTime::from_consensus(reference.lock_time),
            input: reference
                .inputs
                .iter()
                .map(|input| {
                    Ok(TxIn {
                        previous_output: OutPoint {
                            txid: Self::txid(&input.prev_hash)?,
                            vout: input.prev_index,
                        },
                        script_sig: ScriptBuf::from_bytes(input.script_sig.clone()),
                        sequence: Sequence(input.sequence),
                        witness: Witness::new(),
                    })
                })
                .collect::<WalletResult<_>>()?,
            output: reference
                .bin_outputs
                .iter()
                .map(|output| TxOut {
                    value: Amount::from_sat(output.amount),
                    script_pubkey: ScriptBuf::from_bytes(output.script_pubkey.clone()),
                })
                .collect(),
        };
        if transaction.compute_txid() != Self::txid(&reference.hash)? {
            return Err(Self::invalid("Bitcoin reference transaction hash mismatch"));
        }
        Ok(transaction)
    }

    pub fn new(request: &BtcSignTx, account: &BitcoinAccount) -> WalletResult<Self> {
        Self::validate(request)?;
        let keys = request
            .inputs
            .iter()
            .map(|input| account.key(&input.path))
            .collect::<WalletResult<Vec<_>>>()?;
        let mut change_keys = Vec::new();
        let mut outputs = Vec::new();
        for output in &request.outputs {
            if output.multisig.is_some()
                || output.orig_hash.is_some()
                || output.orig_index.is_some()
                || output.payment_req_index.is_some()
                || output.op_return_data.is_some()
            {
                return Err(Self::invalid(
                    "Ledger Bitcoin output metadata or OP_RETURN is not supported yet",
                ));
            }
            let script = if let Some(address) = &output.address {
                if !output.path.is_empty()
                    || output.script_type != BtcOutputScriptType::PayToAddress
                {
                    return Err(Self::invalid(
                        "external Bitcoin output requires address only with PayToAddress",
                    ));
                }
                change_keys.push(None);
                Address::from_str(address)
                    .map_err(|_| Self::invalid("invalid Bitcoin output address"))?
                    .require_network(account.network)
                    .map_err(|_| Self::invalid("Bitcoin output network mismatch"))?
                    .script_pubkey()
            } else {
                if output.script_type != BtcOutputScriptType::PayToWitness {
                    return Err(Self::invalid("Bitcoin change output must be P2WPKH"));
                }
                let key = account.key(&output.path)?;
                if output.path[3] != 1 {
                    return Err(Self::invalid(
                        "Bitcoin change must use the internal branch /1/index",
                    ));
                }
                change_keys.push(Some((
                    key.inner,
                    (
                        account.fingerprint,
                        BitcoinAccount::derivation(&output.path),
                    ),
                )));
                account.address(&output.path)?.script_pubkey()
            };
            outputs.push(TxOut {
                value: Amount::from_sat(output.amount),
                script_pubkey: script,
            });
        }
        let transaction = Transaction {
            version: Version(request.version as i32),
            lock_time: LockTime::from_consensus(request.lock_time),
            input: request
                .inputs
                .iter()
                .map(|input| {
                    Ok(TxIn {
                        previous_output: OutPoint {
                            txid: Self::txid(&input.prev_hash)?,
                            vout: input.prev_index,
                        },
                        script_sig: ScriptBuf::new(),
                        sequence: Sequence(input.sequence),
                        witness: Witness::new(),
                    })
                })
                .collect::<WalletResult<_>>()?,
            output: outputs,
        };
        let mut psbt = Psbt::from_unsigned_tx(transaction)
            .map_err(|_| Self::invalid("invalid unsigned Bitcoin transaction"))?;
        let mut input_total = 0u64;
        for (index, input) in request.inputs.iter().enumerate() {
            let references = request
                .ref_txs
                .iter()
                .filter(|reference| reference.hash == input.prev_hash)
                .collect::<Vec<_>>();
            if references.len() != 1 {
                return Err(Self::invalid(
                    "each Bitcoin input requires exactly one matching full reference transaction",
                ));
            }
            let reference = Self::reference(references[0])?;
            let previous = reference
                .output
                .get(input.prev_index as usize)
                .ok_or_else(|| Self::invalid("Bitcoin previous output index is out of range"))?;
            if previous.value.to_sat() != input.amount
                || previous.script_pubkey != account.address(&input.path)?.script_pubkey()
            {
                return Err(Self::invalid(
                    "Bitcoin input amount or script does not match its reference transaction and derivation path",
                ));
            }
            input_total = input_total
                .checked_add(input.amount)
                .filter(|total| *total <= Amount::MAX_MONEY.to_sat())
                .ok_or_else(|| Self::invalid("Bitcoin input amount exceeds money range"))?;
            psbt.inputs[index].witness_utxo = Some(previous.clone());
            psbt.inputs[index].non_witness_utxo = Some(reference);
            psbt.inputs[index].sighash_type = Some(EcdsaSighashType::All.into());
            psbt.inputs[index].bip32_derivation.insert(
                keys[index].inner,
                (account.fingerprint, BitcoinAccount::derivation(&input.path)),
            );
        }
        let output_total = psbt
            .unsigned_tx
            .output
            .iter()
            .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))
            .ok_or_else(|| Self::invalid("Bitcoin output amount overflow"))?;
        if output_total > input_total {
            return Err(Self::invalid("Bitcoin outputs exceed inputs"));
        }
        for (output, key) in psbt.outputs.iter_mut().zip(change_keys) {
            if let Some((key, source)) = key {
                output.bip32_derivation.insert(key, source);
            }
        }
        Ok(Self { psbt, keys })
    }

    fn verification(message: &str) -> WalletError {
        WalletError::Verification(message.into())
    }

    fn verify_signature(
        &self,
        index: usize,
        signature: &bitcoin::ecdsa::Signature,
        cache: &mut SighashCache<&Transaction>,
    ) -> WalletResult<()> {
        let previous = self.psbt.inputs[index]
            .witness_utxo
            .as_ref()
            .ok_or_else(|| Self::verification("missing Bitcoin previous output"))?;
        let hash = cache
            .p2wpkh_signature_hash(
                index,
                &previous.script_pubkey,
                previous.value,
                EcdsaSighashType::All,
            )
            .map_err(|_| Self::verification("cannot compute Bitcoin signing hash"))?;
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(hash.to_byte_array()),
                &signature.signature,
                &self.keys[index].inner,
            )
            .map_err(|_| {
                Self::verification(
                    "Ledger Bitcoin signature does not match the requested transaction",
                )
            })
    }

    pub fn finish(
        self,
        yielded: Vec<(usize, SignPsbtYieldedObject)>,
    ) -> WalletResult<LedgerBitcoinTxResult> {
        let mut signatures = vec![Vec::new(); self.keys.len()];
        let mut transaction = self.psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        for (index, object) in yielded {
            let SignPsbtYieldedObject::Partial(PartialSignature::Sig(key, signature)) = object
            else {
                return Err(Self::verification("unexpected Bitcoin signature type"));
            };
            if self.keys.get(index) != Some(&key)
                || !signatures[index].is_empty()
                || signature.sighash_type != EcdsaSighashType::All
            {
                return Err(Self::verification(
                    "unexpected Bitcoin signature key, index or sighash",
                ));
            }
            self.verify_signature(index, &signature, &mut cache)?;
            transaction.input[index].witness = Witness::p2wpkh(&signature, &key.inner);
            signatures[index] = signature.signature.serialize_der().to_vec();
        }
        if signatures.iter().any(Vec::is_empty) {
            return Err(Self::verification(
                "Ledger did not sign every Bitcoin input",
            ));
        }
        Ok(LedgerBitcoinTxResult {
            signatures,
            serialized_transaction: bitcoin::consensus::serialize(&transaction),
            transaction_id: transaction.compute_txid().to_string(),
        })
    }
}

#[cfg(test)]
#[path = "bitcoin_vector_tests.rs"]
mod vector_tests;
