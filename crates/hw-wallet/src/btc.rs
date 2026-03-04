use std::collections::HashMap;

use serde::Deserialize;
use trezor_connect::thp::{
    BtcInputScriptType, BtcOutputScriptType, BtcRefTx, BtcRefTxInput, BtcRefTxOutput, BtcSignInput,
    BtcSignOutput, BtcSignTx, SignTxRequest,
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
}

#[derive(Debug, Deserialize)]
pub struct TxInputOutput {
    pub address: Option<String>,
    pub path: Option<String>,
    pub amount: String,
    #[serde(default = "default_output_script_type")]
    pub script_type: String,
    pub op_return_data: Option<String>,
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

    validate_ref_txs_for_inputs(&inputs, &ref_txs)?;

    Ok(SignTxRequest::bitcoin(BtcSignTx {
        version,
        lock_time,
        inputs,
        outputs,
        ref_txs,
        payment_reqs: Vec::new(),
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
