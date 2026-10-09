use crate::thp::types::{BtcInputScriptType, BtcOutputScriptType};

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum BitcoinInputScriptTypeProto {
    SpendAddress = 0,
    SpendMultisig = 1,
    External = 2,
    SpendWitness = 3,
    SpendP2ShWitness = 4,
    SpendTaproot = 5,
}

impl From<BtcInputScriptType> for BitcoinInputScriptTypeProto {
    fn from(script_type: BtcInputScriptType) -> Self {
        match script_type {
            BtcInputScriptType::SpendAddress => Self::SpendAddress,
            BtcInputScriptType::SpendMultisig => Self::SpendMultisig,
            BtcInputScriptType::External => Self::External,
            BtcInputScriptType::SpendWitness => Self::SpendWitness,
            BtcInputScriptType::SpendP2shWitness => Self::SpendP2ShWitness,
            BtcInputScriptType::SpendTaproot => Self::SpendTaproot,
        }
    }
}

impl BitcoinInputScriptTypeProto {
    pub(crate) fn wire(script_type: BtcInputScriptType) -> i32 {
        Self::from(script_type) as i32
    }

    pub(crate) fn wire_for_path(path: &[u32]) -> Option<i32> {
        BtcInputScriptType::from_path(path).map(Self::wire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum BitcoinOutputScriptTypeProto {
    PayToAddress = 0,
    PayToScriptHash = 1,
    PayToMultisig = 2,
    PayToOpReturn = 3,
    PayToWitness = 4,
    PayToP2ShWitness = 5,
    PayToTaproot = 6,
}

impl From<BtcOutputScriptType> for BitcoinOutputScriptTypeProto {
    fn from(script_type: BtcOutputScriptType) -> Self {
        match script_type {
            BtcOutputScriptType::PayToAddress => Self::PayToAddress,
            BtcOutputScriptType::PayToScriptHash => Self::PayToScriptHash,
            BtcOutputScriptType::PayToMultisig => Self::PayToMultisig,
            BtcOutputScriptType::PayToOpReturn => Self::PayToOpReturn,
            BtcOutputScriptType::PayToWitness => Self::PayToWitness,
            BtcOutputScriptType::PayToP2shWitness => Self::PayToP2ShWitness,
            BtcOutputScriptType::PayToTaproot => Self::PayToTaproot,
        }
    }
}
