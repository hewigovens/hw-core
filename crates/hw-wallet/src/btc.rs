use std::collections::HashMap;

use serde::Deserialize;
use trezor_connect::thp::{
    BtcInputScriptType, BtcOrigTx, BtcOutputScriptType, BtcPaymentRequest, BtcPaymentRequestAmount,
    BtcPaymentRequestMemo, BtcRefTx, BtcRefTxInput, BtcRefTxOutput, BtcSignInput, BtcSignOutput,
    BtcSignTx, SignTxRequest,
};

use crate::bip32::parse_bip32_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

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

#[derive(Debug, Deserialize)]
pub struct TxInputInput {
    pub path: String,
    pub prev_hash: String,
    pub prev_index: u32,
    pub amount: String,
    #[serde(default = "default_sequence")]
    pub sequence: u32,
    #[serde(default = "default_input_script_type")]
    pub script_type: String,
    pub script_sig: Option<String>,
    pub witness: Option<String>,
    pub orig_hash: Option<String>,
    pub orig_index: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct TxInputOutput {
    pub address: Option<String>,
    pub path: Option<String>,
    pub amount: String,
    #[serde(default = "default_output_script_type")]
    pub script_type: String,
    pub op_return_data: Option<String>,
    pub orig_hash: Option<String>,
    pub orig_index: Option<u32>,
    #[serde(default)]
    pub payment_req_index: Option<u32>,
}

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

#[derive(Debug, Deserialize)]
pub struct TxInputPaymentRequest {
    pub nonce: Option<String>,
    pub recipient_name: String,
    #[serde(default)]
    pub memos: Vec<TxInputPaymentRequestMemo>,
    pub amount: Option<String>,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct TxInputPaymentRequestMemo {
    #[serde(rename = "type")]
    pub memo_type: String,
    pub title: Option<String>,
    pub text: Option<String>,
    pub address: Option<String>,
    pub path: Option<String>,
    pub mac: Option<String>,
    pub coin_type: Option<u32>,
    pub amount: Option<String>,
}

fn default_version() -> u32 {
    2
}

fn default_sequence() -> u32 {
    0xffff_ffff
}

fn default_input_script_type() -> String {
    "spendwitness".to_string()
}

fn default_output_script_type() -> String {
    "paytoaddress".to_string()
}

pub fn parse_tx_json(json: &str) -> WalletResult<TxInput> {
    serde_json::from_str(json)
        .map_err(|err| WalletError::Signing(format!("invalid bitcoin tx JSON: {err}")))
}

pub fn build_sign_tx_request(tx: TxInput) -> WalletResult<SignTxRequest> {
    let TxInput {
        version,
        lock_time,
        chunkify,
        inputs: raw_inputs,
        outputs: raw_outputs,
        ref_txs: raw_ref_txs,
        orig_txs: raw_orig_txs,
        payment_reqs: raw_payment_reqs,
    } = tx;

    if raw_inputs.is_empty() {
        return Err(WalletError::Signing(
            "bitcoin tx must contain at least one input".into(),
        ));
    }
    if raw_outputs.is_empty() {
        return Err(WalletError::Signing(
            "bitcoin tx must contain at least one output".into(),
        ));
    }

    let inputs = raw_inputs
        .into_iter()
        .map(|input| {
            let path = parse_bip32_path(&input.path)?;
            let prev_hash = parse_hash32("prev_hash", &input.prev_hash)?;
            let amount = parse_sats(&input.amount)?;
            let script_type = parse_input_script_type(&input.script_type)?;
            Ok(BtcSignInput {
                path,
                prev_hash,
                prev_index: input.prev_index,
                amount,
                sequence: input.sequence,
                script_type,
                script_sig: input.script_sig.as_deref().map(decode).transpose()?,
                witness: input.witness.as_deref().map(decode).transpose()?,
                orig_hash: input
                    .orig_hash
                    .as_deref()
                    .map(|value| parse_hash32("inputs.orig_hash", value))
                    .transpose()?,
                orig_index: input.orig_index,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    let outputs = raw_outputs
        .into_iter()
        .map(|output| {
            if output.address.is_none() && output.path.is_none() {
                return Err(WalletError::Signing(
                    "bitcoin output requires either address or path".into(),
                ));
            }
            if output.address.is_some() && output.path.is_some() {
                return Err(WalletError::Signing(
                    "bitcoin output cannot specify both address and path".into(),
                ));
            }

            let amount = parse_sats(&output.amount)?;
            let script_type = parse_output_script_type(&output.script_type)?;
            let path = output
                .path
                .as_deref()
                .map(parse_bip32_path)
                .transpose()?
                .unwrap_or_default();
            let op_return_data = output.op_return_data.as_deref().map(decode).transpose()?;
            Ok(BtcSignOutput {
                address: output.address,
                path,
                amount,
                script_type,
                op_return_data,
                orig_hash: output
                    .orig_hash
                    .as_deref()
                    .map(|value| parse_hash32("outputs.orig_hash", value))
                    .transpose()?,
                orig_index: output.orig_index,
                payment_req_index: output.payment_req_index,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    let ref_txs = raw_ref_txs
        .into_iter()
        .map(|tx| {
            let hash = parse_hash32("ref_txs.hash", &tx.hash)?;
            let inputs = tx
                .inputs
                .into_iter()
                .map(|input| {
                    Ok(BtcRefTxInput {
                        prev_hash: parse_hash32("ref_txs.inputs.prev_hash", &input.prev_hash)?,
                        prev_index: input.prev_index,
                        script_sig: decode(&input.script_sig)?,
                        sequence: input.sequence,
                    })
                })
                .collect::<WalletResult<Vec<_>>>()?;
            let bin_outputs = tx
                .bin_outputs
                .into_iter()
                .map(|output| {
                    Ok(BtcRefTxOutput {
                        amount: parse_sats(&output.amount)?,
                        script_pubkey: decode(&output.script_pubkey)?,
                    })
                })
                .collect::<WalletResult<Vec<_>>>()?;
            let extra_data = tx.extra_data.as_deref().map(decode).transpose()?;
            Ok(BtcRefTx {
                hash,
                version: tx.version,
                lock_time: tx.lock_time,
                inputs,
                bin_outputs,
                extra_data,
                timestamp: tx.timestamp,
                version_group_id: tx.version_group_id,
                expiry: tx.expiry,
                branch_id: tx.branch_id,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    let orig_txs = raw_orig_txs
        .into_iter()
        .map(|tx| {
            let hash = parse_hash32("orig_txs.hash", &tx.hash)?;
            let inputs = tx
                .inputs
                .into_iter()
                .map(|input| {
                    let path = parse_bip32_path(&input.path)?;
                    let prev_hash = parse_hash32("orig_txs.inputs.prev_hash", &input.prev_hash)?;
                    let amount = parse_sats(&input.amount)?;
                    let script_type = parse_input_script_type(&input.script_type)?;
                    Ok(BtcSignInput {
                        path,
                        prev_hash,
                        prev_index: input.prev_index,
                        amount,
                        sequence: input.sequence,
                        script_type,
                        script_sig: input.script_sig.as_deref().map(decode).transpose()?,
                        witness: input.witness.as_deref().map(decode).transpose()?,
                        orig_hash: input
                            .orig_hash
                            .as_deref()
                            .map(|value| parse_hash32("orig_txs.inputs.orig_hash", value))
                            .transpose()?,
                        orig_index: input.orig_index,
                    })
                })
                .collect::<WalletResult<Vec<_>>>()?;
            let outputs = tx
                .outputs
                .into_iter()
                .map(|output| {
                    if output.address.is_none() && output.path.is_none() {
                        return Err(WalletError::Signing(
                            "bitcoin original tx output requires either address or path".into(),
                        ));
                    }
                    if output.address.is_some() && output.path.is_some() {
                        return Err(WalletError::Signing(
                            "bitcoin original tx output cannot specify both address and path"
                                .into(),
                        ));
                    }

                    let amount = parse_sats(&output.amount)?;
                    let script_type = parse_output_script_type(&output.script_type)?;
                    let path = output
                        .path
                        .as_deref()
                        .map(parse_bip32_path)
                        .transpose()?
                        .unwrap_or_default();
                    let op_return_data =
                        output.op_return_data.as_deref().map(decode).transpose()?;
                    Ok(BtcSignOutput {
                        address: output.address,
                        path,
                        amount,
                        script_type,
                        op_return_data,
                        orig_hash: output
                            .orig_hash
                            .as_deref()
                            .map(|value| parse_hash32("orig_txs.outputs.orig_hash", value))
                            .transpose()?,
                        orig_index: output.orig_index,
                        payment_req_index: output.payment_req_index,
                    })
                })
                .collect::<WalletResult<Vec<_>>>()?;
            let extra_data = tx.extra_data.as_deref().map(decode).transpose()?;
            Ok(BtcOrigTx {
                hash,
                version: tx.version,
                lock_time: tx.lock_time,
                inputs,
                outputs,
                extra_data,
                timestamp: tx.timestamp,
                version_group_id: tx.version_group_id,
                expiry: tx.expiry,
                branch_id: tx.branch_id,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    let payment_reqs = raw_payment_reqs
        .into_iter()
        .map(|payment_req| {
            let memos = payment_req
                .memos
                .into_iter()
                .map(|memo| match memo.memo_type.as_str() {
                    "text" => Ok(BtcPaymentRequestMemo::Text {
                        text: memo.text.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request text memo requires text".into(),
                            )
                        })?,
                    }),
                    "text_details" => Ok(BtcPaymentRequestMemo::TextDetails {
                        title: memo.title.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request text_details memo requires title".into(),
                            )
                        })?,
                        text: memo.text.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request text_details memo requires text".into(),
                            )
                        })?,
                    }),
                    "refund" => Ok(BtcPaymentRequestMemo::Refund {
                        address: memo.address.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request refund memo requires address".into(),
                            )
                        })?,
                        path: parse_bip32_path(memo.path.as_deref().ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request refund memo requires path".into(),
                            )
                        })?)?,
                        mac: decode(memo.mac.as_deref().ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request refund memo requires mac".into(),
                            )
                        })?)?,
                    }),
                    "coin_purchase" => Ok(BtcPaymentRequestMemo::CoinPurchase {
                        coin_type: memo.coin_type.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request coin_purchase memo requires coin_type"
                                    .into(),
                            )
                        })?,
                        amount: memo.amount.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request coin_purchase memo requires amount".into(),
                            )
                        })?,
                        address: memo.address.ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request coin_purchase memo requires address"
                                    .into(),
                            )
                        })?,
                        path: parse_bip32_path(memo.path.as_deref().ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request coin_purchase memo requires path".into(),
                            )
                        })?)?,
                        mac: decode(memo.mac.as_deref().ok_or_else(|| {
                            WalletError::Signing(
                                "bitcoin payment request coin_purchase memo requires mac".into(),
                            )
                        })?)?,
                    }),
                    other => Err(WalletError::Signing(format!(
                        "unsupported bitcoin payment request memo type '{other}'"
                    ))),
                })
                .collect::<WalletResult<Vec<_>>>()?;

            Ok(BtcPaymentRequest {
                nonce: payment_req.nonce.as_deref().map(decode).transpose()?,
                recipient_name: payment_req.recipient_name,
                memos,
                amount: payment_req
                    .amount
                    .as_deref()
                    .map(parse_sats)
                    .transpose()?
                    .map(BtcPaymentRequestAmount::from_sats),
                signature: decode(&payment_req.signature)?,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    validate_ref_txs_for_inputs(&inputs, &ref_txs)?;
    validate_original_tx_links(&inputs, &outputs, &orig_txs)?;

    Ok(SignTxRequest::bitcoin(BtcSignTx {
        version,
        lock_time,
        inputs,
        outputs,
        ref_txs,
        orig_txs,
        payment_reqs,
        chunkify,
    }))
}

fn parse_hash32(field: &str, value: &str) -> WalletResult<Vec<u8>> {
    let decoded = decode(value)?;
    if decoded.len() != 32 {
        return Err(WalletError::Signing(format!(
            "{field} must be 32 bytes, got {} bytes",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn validate_ref_txs_for_inputs(inputs: &[BtcSignInput], ref_txs: &[BtcRefTx]) -> WalletResult<()> {
    let mut ref_txs_by_hash: HashMap<Vec<u8>, &BtcRefTx> = HashMap::new();
    for ref_tx in ref_txs {
        if ref_txs_by_hash
            .insert(ref_tx.hash.clone(), ref_tx)
            .is_some()
        {
            return Err(WalletError::Signing(format!(
                "duplicate ref_txs hash {}",
                ::hex::encode(&ref_tx.hash)
            )));
        }
    }

    for (input_index, input) in inputs.iter().enumerate() {
        let Some(ref_tx) = ref_txs_by_hash.get(&input.prev_hash) else {
            return Err(WalletError::Signing(format!(
                "ref_txs must include transaction {} referenced by input {}",
                ::hex::encode(&input.prev_hash),
                input_index
            )));
        };
        let prev_index = input.prev_index as usize;
        if prev_index >= ref_tx.bin_outputs.len() {
            return Err(WalletError::Signing(format!(
                "input {input_index} prev_index {} out of bounds for ref_txs hash {} (outputs={})",
                input.prev_index,
                ::hex::encode(&input.prev_hash),
                ref_tx.bin_outputs.len()
            )));
        }
    }

    Ok(())
}

fn validate_original_tx_links(
    inputs: &[BtcSignInput],
    outputs: &[BtcSignOutput],
    orig_txs: &[BtcOrigTx],
) -> WalletResult<()> {
    let mut orig_txs_by_hash: HashMap<Vec<u8>, &BtcOrigTx> = HashMap::new();
    for orig_tx in orig_txs {
        if orig_txs_by_hash
            .insert(orig_tx.hash.clone(), orig_tx)
            .is_some()
        {
            return Err(WalletError::Signing(format!(
                "duplicate original transaction hash {}",
                hex::encode(&orig_tx.hash)
            )));
        }
    }

    for (index, input) in inputs.iter().enumerate() {
        if input.orig_hash.is_some() != input.orig_index.is_some() {
            return Err(WalletError::Signing(format!(
                "inputs[{index}] must specify both orig_hash and orig_index"
            )));
        }
        if let (Some(orig_hash), Some(orig_index)) = (&input.orig_hash, input.orig_index) {
            let orig_tx = orig_txs_by_hash.get(orig_hash).ok_or_else(|| {
                WalletError::Signing(format!(
                    "missing original transaction {} for inputs[{index}]",
                    hex::encode(orig_hash)
                ))
            })?;
            if usize::try_from(orig_index)
                .ok()
                .is_none_or(|idx| idx >= orig_tx.inputs.len())
            {
                return Err(WalletError::Signing(format!(
                    "orig_index {orig_index} out of bounds for inputs[{index}]"
                )));
            }
        }
    }

    for (index, output) in outputs.iter().enumerate() {
        if output.orig_hash.is_some() != output.orig_index.is_some() {
            return Err(WalletError::Signing(format!(
                "outputs[{index}] must specify both orig_hash and orig_index"
            )));
        }
        if let (Some(orig_hash), Some(orig_index)) = (&output.orig_hash, output.orig_index) {
            let orig_tx = orig_txs_by_hash.get(orig_hash).ok_or_else(|| {
                WalletError::Signing(format!(
                    "missing original transaction {} for outputs[{index}]",
                    hex::encode(orig_hash)
                ))
            })?;
            if usize::try_from(orig_index)
                .ok()
                .is_none_or(|idx| idx >= orig_tx.outputs.len())
            {
                return Err(WalletError::Signing(format!(
                    "orig_index {orig_index} out of bounds for outputs[{index}]"
                )));
            }
        }
    }

    Ok(())
}

fn parse_sats(value: &str) -> WalletResult<u64> {
    if value.starts_with("0x") || value.starts_with("0X") {
        return u64::from_str_radix(&value[2..], 16).map_err(|err| {
            WalletError::Signing(format!("invalid satoshi amount '{value}': {err}"))
        });
    }
    value
        .parse::<u64>()
        .map_err(|err| WalletError::Signing(format!("invalid satoshi amount '{value}': {err}")))
}

fn parse_input_script_type(value: &str) -> WalletResult<BtcInputScriptType> {
    let value = value.to_ascii_lowercase();
    match value.as_str() {
        "spendaddress" | "p2pkh" => Ok(BtcInputScriptType::SpendAddress),
        "spendmultisig" => Ok(BtcInputScriptType::SpendMultisig),
        "external" => Ok(BtcInputScriptType::External),
        "spendwitness" | "p2wpkh" => Ok(BtcInputScriptType::SpendWitness),
        "spendp2shwitness" | "p2shwpkh" => Ok(BtcInputScriptType::SpendP2shWitness),
        "spendtaproot" | "p2tr" => Ok(BtcInputScriptType::SpendTaproot),
        _ => Err(WalletError::Signing(format!(
            "unsupported bitcoin input script type '{value}'"
        ))),
    }
}

fn parse_output_script_type(value: &str) -> WalletResult<BtcOutputScriptType> {
    let value = value.to_ascii_lowercase();
    match value.as_str() {
        "paytoaddress" | "address" => Ok(BtcOutputScriptType::PayToAddress),
        "paytoscripthash" => Ok(BtcOutputScriptType::PayToScriptHash),
        "paytomultisig" => Ok(BtcOutputScriptType::PayToMultisig),
        "paytoopreturn" => Ok(BtcOutputScriptType::PayToOpReturn),
        "paytowitness" => Ok(BtcOutputScriptType::PayToWitness),
        "paytop2shwitness" => Ok(BtcOutputScriptType::PayToP2shWitness),
        "paytotaproot" => Ok(BtcOutputScriptType::PayToTaproot),
        _ => Err(WalletError::Signing(format!(
            "unsupported bitcoin output script type '{value}'"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hw_chain::Chain;

    const BTC_PARSE_WITH_REF_TXS: &str =
        include_str!("../../../tests/data/bitcoin/btc_parse_with_ref_txs.json");
    const BTC_BUILD_WITH_REF_TXS: &str =
        include_str!("../../../tests/data/bitcoin/btc_build_with_ref_txs.json");
    const BTC_MISSING_REF_TXS: &str =
        include_str!("../../../tests/data/bitcoin/btc_missing_ref_txs.json");
    const BTC_PREV_INDEX_OOB: &str =
        include_str!("../../../tests/data/bitcoin/btc_prev_index_oob.json");
    const BTC_RBF_WITH_PAYMENT_REQ: &str =
        include_str!("../../../tests/data/bitcoin/btc_rbf_with_payment_req.json");

    #[test]
    fn parse_btc_tx_json() {
        let tx = parse_tx_json(BTC_PARSE_WITH_REF_TXS).unwrap();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.ref_txs.len(), 1);
    }

    #[test]
    fn build_btc_sign_request() {
        let tx = parse_tx_json(BTC_BUILD_WITH_REF_TXS).unwrap();
        let request = build_sign_tx_request(tx).unwrap();
        assert_eq!(request.chain, Chain::Bitcoin);
        let btc = request.btc.unwrap();
        assert_eq!(btc.inputs[0].amount, 100);
        assert_eq!(btc.outputs[0].amount, 90);
        assert_eq!(btc.ref_txs.len(), 1);
    }

    #[test]
    fn build_btc_sign_request_with_orig_txs_and_payment_reqs() {
        let tx = parse_tx_json(BTC_RBF_WITH_PAYMENT_REQ).unwrap();
        let request = build_sign_tx_request(tx).unwrap();
        let btc = request.btc.unwrap();
        assert_eq!(btc.orig_txs.len(), 1);
        assert_eq!(btc.payment_reqs.len(), 1);
        assert_eq!(
            btc.inputs[0].orig_hash.as_deref(),
            Some([0x11; 32].as_slice())
        );
        assert_eq!(btc.outputs[0].payment_req_index, Some(0));
    }

    #[test]
    fn build_btc_sign_request_fails_when_ref_tx_is_missing() {
        let tx = parse_tx_json(BTC_MISSING_REF_TXS).unwrap();
        let err = build_sign_tx_request(tx).unwrap_err();
        assert!(err
            .to_string()
            .contains("ref_txs must include transaction 1111111111111111111111111111111111111111111111111111111111111111"));
    }

    #[test]
    fn build_btc_sign_request_fails_on_prev_index_bounds() {
        let tx = parse_tx_json(BTC_PREV_INDEX_OOB).unwrap();
        let err = build_sign_tx_request(tx).unwrap_err();
        assert!(
            err.to_string()
                .contains("input 0 prev_index 2 out of bounds for ref_txs hash")
        );
    }
}
