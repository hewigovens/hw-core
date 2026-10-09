use serde::Deserialize;
use trezor_connect::thp::{BtcMultisig, BtcOutputScriptType, BtcSignOutput};

use super::multisig::TxInputMultisig;
use super::owner::TxOwner;
use super::sats::parse_sats;
use super::script_type::OutputScriptTypeExt;
use crate::bip32::parse_bip32_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_hash32};

#[derive(Debug, Deserialize)]
pub struct TxInputOutput {
    pub address: Option<String>,
    pub path: Option<String>,
    pub amount: String,
    pub script_type: Option<String>,
    pub multisig: Option<TxInputMultisig>,
    pub op_return_data: Option<String>,
    pub orig_hash: Option<String>,
    pub orig_index: Option<u32>,
    #[serde(default)]
    pub payment_req_index: Option<u32>,
}

impl TxInputOutput {
    pub(super) fn into_sign_output(self, owner: TxOwner) -> WalletResult<BtcSignOutput> {
        let label = owner.output_label();
        let explicit_script_type = self
            .script_type
            .as_deref()
            .map(BtcOutputScriptType::parse)
            .transpose()?;
        let path = self.path.as_deref().map(parse_bip32_path).transpose()?;
        let script_type = match (self.address.as_deref(), path.as_deref()) {
            (Some(_), Some(_)) => {
                return Err(WalletError::Signing(format!(
                    "{label} cannot specify both address and path"
                )));
            }
            (Some(_), None) => BtcOutputScriptType::for_address(explicit_script_type, label)?,
            (None, Some(path)) => {
                BtcOutputScriptType::for_change(explicit_script_type, path, label)?
            }
            (None, None) => match explicit_script_type {
                Some(BtcOutputScriptType::PayToOpReturn) => BtcOutputScriptType::PayToOpReturn,
                Some(
                    BtcOutputScriptType::PayToAddress
                    | BtcOutputScriptType::PayToScriptHash
                    | BtcOutputScriptType::PayToMultisig
                    | BtcOutputScriptType::PayToWitness
                    | BtcOutputScriptType::PayToP2shWitness
                    | BtcOutputScriptType::PayToTaproot,
                )
                | None => {
                    return Err(WalletError::Signing(format!(
                        "{label} requires either address or path"
                    )));
                }
            },
        };

        let amount = parse_sats(&self.amount)?;
        let op_return_data = self.op_return_data.as_deref().map(decode).transpose()?;
        if script_type == BtcOutputScriptType::PayToOpReturn && op_return_data.is_none() {
            return Err(WalletError::Signing(format!(
                "{label} with script_type PayToOpReturn requires op_return_data"
            )));
        }
        if script_type == BtcOutputScriptType::PayToOpReturn && amount != 0 {
            return Err(WalletError::Signing(format!(
                "{label} with script_type PayToOpReturn must have zero amount, got {amount}"
            )));
        }
        let multisig = self.multisig.map(BtcMultisig::try_from).transpose()?;
        if script_type == BtcOutputScriptType::PayToMultisig && multisig.is_none() {
            return Err(WalletError::Signing(
                "bitcoin PayToMultisig output requires multisig metadata".into(),
            ));
        }
        Ok(BtcSignOutput {
            address: self.address,
            path: path.unwrap_or_default(),
            amount,
            script_type,
            multisig,
            op_return_data,
            orig_hash: self
                .orig_hash
                .as_deref()
                .map(|value| decode_hash32(owner.output_orig_hash_field(), value))
                .transpose()?,
            orig_index: self.orig_index,
            payment_req_index: self.payment_req_index,
        })
    }
}
