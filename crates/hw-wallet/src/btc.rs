use serde::Deserialize;
use trezor_connect::thp::{
    BtcInputScriptType, BtcOutputScriptType, BtcSignInput, BtcSignOutput, BtcSignTx, SignTxRequest,
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

    let inputs = tx
        .inputs
        .into_iter()
        .map(|input| {
            let path = parse_bip32_path(&input.path)?;
            let prev_hash = decode(&input.prev_hash)?;
            if prev_hash.len() != 32 {
                return Err(WalletError::Signing(format!(
                    "prev_hash must be 32 bytes, got {} bytes",
                    prev_hash.len()
                )));
            }
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

    let outputs = tx
        .outputs
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
                .transpose()
                .map_err(|err| WalletError::Signing(err.to_string()))?
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

    Ok(SignTxRequest::bitcoin(BtcSignTx {
        version: tx.version,
        lock_time: tx.lock_time,
        inputs,
        outputs,
        chunkify: tx.chunkify,
    }))
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

    #[test]
    fn parse_btc_tx_json() {
        let tx = parse_tx_json(
            r#"{
                "version": 2,
                "lock_time": 0,
                "inputs": [
                    {
                        "path": "m/84'/0'/0'/0/0",
                        "prev_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "prev_index": 1,
                        "amount": "12345"
                    }
                ],
                "outputs": [
                    {
                        "address": "bc1qexample0000000000000000000000000000000000",
                        "amount": "12000"
                    }
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn build_btc_sign_request() {
        let tx = parse_tx_json(
            r#"{
                "inputs": [
                    {
                        "path": "m/84'/0'/0'/0/0",
                        "prev_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "prev_index": 0,
                        "amount": "0x64"
                    }
                ],
                "outputs": [
                    {
                        "path": "m/84'/0'/0'/1/0",
                        "amount": "90"
                    }
                ]
            }"#,
        )
        .unwrap();
        let request = build_sign_tx_request(tx).unwrap();
        assert_eq!(request.chain, Chain::Bitcoin);
        let btc = request.btc.unwrap();
        assert_eq!(btc.inputs[0].amount, 100);
        assert_eq!(btc.outputs[0].amount, 90);
    }
}
