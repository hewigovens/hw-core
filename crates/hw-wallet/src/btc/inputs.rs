use serde::Deserialize;
use trezor_connect::thp::{BtcInputScriptType, BtcMultisig, BtcSignInput};

use super::multisig::TxInputMultisig;
use super::owner::TxOwner;
use super::sats::parse_sats;
use super::script_type::InputScriptTypeExt;
use crate::bip32::parse_bip32_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_hash32};

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
    pub multisig: Option<TxInputMultisig>,
    pub script_sig: Option<String>,
    pub witness: Option<String>,
    pub orig_hash: Option<String>,
    pub orig_index: Option<u32>,
}

pub(super) fn default_sequence() -> u32 {
    0xffff_ffff
}

fn default_input_script_type() -> String {
    "spendwitness".to_string()
}

impl TxInputInput {
    pub(super) fn into_sign_input(self, owner: TxOwner) -> WalletResult<BtcSignInput> {
        let path = parse_bip32_path(&self.path)?;
        let prev_hash = decode_hash32(owner.input_prev_hash_field(), &self.prev_hash)?;
        let amount = parse_sats(&self.amount)?;
        let script_type = BtcInputScriptType::parse(&self.script_type)?;
        let multisig = self.multisig.map(BtcMultisig::try_from).transpose()?;
        if script_type == BtcInputScriptType::SpendMultisig && multisig.is_none() {
            return Err(WalletError::Signing(
                "bitcoin input with script_type SpendMultisig requires multisig metadata".into(),
            ));
        }
        Ok(BtcSignInput {
            path,
            prev_hash,
            prev_index: self.prev_index,
            amount,
            sequence: self.sequence,
            script_type,
            multisig,
            script_sig: self.script_sig.as_deref().map(decode).transpose()?,
            witness: self.witness.as_deref().map(decode).transpose()?,
            orig_hash: self
                .orig_hash
                .as_deref()
                .map(|value| decode_hash32(owner.input_orig_hash_field(), value))
                .transpose()?,
            orig_index: self.orig_index,
        })
    }
}
