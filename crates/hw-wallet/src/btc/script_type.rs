use trezor_connect::thp::{BtcInputScriptType, BtcOutputScriptType};

use crate::bip32::HARDENED;
use crate::error::{WalletError, WalletResult};

pub(super) trait InputScriptTypeExt: Sized {
    fn parse(value: &str) -> WalletResult<Self>;
}

impl InputScriptTypeExt for BtcInputScriptType {
    fn parse(value: &str) -> WalletResult<Self> {
        let value = value.to_ascii_lowercase();
        match value.as_str() {
            "spendaddress" | "p2pkh" => Ok(Self::SpendAddress),
            "spendmultisig" => Ok(Self::SpendMultisig),
            "external" => Ok(Self::External),
            "spendwitness" | "p2wpkh" => Ok(Self::SpendWitness),
            "spendp2shwitness" | "p2shwpkh" => Ok(Self::SpendP2shWitness),
            "spendtaproot" | "p2tr" => Ok(Self::SpendTaproot),
            _ => Err(WalletError::Signing(format!(
                "unsupported bitcoin input script type '{value}'"
            ))),
        }
    }
}

pub(super) trait OutputScriptTypeExt: Sized {
    fn parse(value: &str) -> WalletResult<Self>;
    fn for_address(explicit: Option<Self>, label: &str) -> WalletResult<Self>;
    fn for_change(explicit: Option<Self>, path: &[u32], label: &str) -> WalletResult<Self>;
    fn for_change_path(path: &[u32]) -> Self;
}

impl OutputScriptTypeExt for BtcOutputScriptType {
    fn parse(value: &str) -> WalletResult<Self> {
        let value = value.to_ascii_lowercase();
        match value.as_str() {
            "paytoaddress" | "address" => Ok(Self::PayToAddress),
            "paytoscripthash" => Ok(Self::PayToScriptHash),
            "paytomultisig" => Ok(Self::PayToMultisig),
            "paytoopreturn" => Ok(Self::PayToOpReturn),
            "paytowitness" => Ok(Self::PayToWitness),
            "paytop2shwitness" => Ok(Self::PayToP2shWitness),
            "paytotaproot" => Ok(Self::PayToTaproot),
            _ => Err(WalletError::Signing(format!(
                "unsupported bitcoin output script type '{value}'"
            ))),
        }
    }

    // Suite 344051e7e: outputs paying to an address default to PAYTOADDRESS and reject anything else.
    fn for_address(explicit: Option<Self>, label: &str) -> WalletResult<Self> {
        match explicit {
            None | Some(Self::PayToAddress) => Ok(Self::PayToAddress),
            Some(
                other @ (Self::PayToScriptHash
                | Self::PayToMultisig
                | Self::PayToOpReturn
                | Self::PayToWitness
                | Self::PayToP2shWitness
                | Self::PayToTaproot),
            ) => Err(WalletError::Signing(format!(
                "{label} with address must use script_type PayToAddress, got {other:?}"
            ))),
        }
    }

    fn for_change(explicit: Option<Self>, path: &[u32], label: &str) -> WalletResult<Self> {
        match explicit {
            None => Ok(Self::for_change_path(path)),
            Some(
                script_type @ (Self::PayToAddress
                | Self::PayToMultisig
                | Self::PayToWitness
                | Self::PayToP2shWitness
                | Self::PayToTaproot),
            ) => Ok(script_type),
            Some(other @ (Self::PayToScriptHash | Self::PayToOpReturn)) => {
                Err(WalletError::Signing(format!(
                    "{label} with path cannot use script_type {other:?}"
                )))
            }
        }
    }

    // Mirrors Suite getOutputScriptType; unknown purposes fall back to the protobuf default PAYTOADDRESS.
    fn for_change_path(path: &[u32]) -> Self {
        let unhardened = |index: usize| path.get(index).map(|part| part & !HARDENED);
        match unhardened(0) {
            Some(48) => match unhardened(3) {
                Some(0) => Self::PayToMultisig,
                Some(1) => Self::PayToP2shWitness,
                Some(2) => Self::PayToWitness,
                _ => Self::PayToAddress,
            },
            Some(49) => Self::PayToP2shWitness,
            Some(84) => Self::PayToWitness,
            Some(86 | 10025) => Self::PayToTaproot,
            _ => Self::PayToAddress,
        }
    }
}
