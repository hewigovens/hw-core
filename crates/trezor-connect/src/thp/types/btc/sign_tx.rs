use super::{BtcMultisig, BtcOrigTx, BtcPaymentRequest, BtcRefTx};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcInputScriptType {
    SpendAddress,
    SpendMultisig,
    External,
    SpendWitness,
    SpendP2shWitness,
    SpendTaproot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcOutputScriptType {
    PayToAddress,
    PayToScriptHash,
    PayToMultisig,
    PayToOpReturn,
    PayToWitness,
    PayToP2shWitness,
    PayToTaproot,
}

#[derive(Debug, Clone)]
pub struct BtcSignInput {
    pub path: Vec<u32>,
    pub prev_hash: Vec<u8>,
    pub prev_index: u32,
    pub amount: u64,
    pub sequence: u32,
    pub script_type: BtcInputScriptType,
    pub multisig: Option<BtcMultisig>,
    pub script_sig: Option<Vec<u8>>,
    pub witness: Option<Vec<u8>>,
    pub orig_hash: Option<Vec<u8>>,
    pub orig_index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct BtcSignOutput {
    pub address: Option<String>,
    pub path: Vec<u32>,
    pub amount: u64,
    pub script_type: BtcOutputScriptType,
    pub multisig: Option<BtcMultisig>,
    pub op_return_data: Option<Vec<u8>>,
    pub orig_hash: Option<Vec<u8>>,
    pub orig_index: Option<u32>,
    pub payment_req_index: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct BtcSignTx {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<BtcSignInput>,
    pub outputs: Vec<BtcSignOutput>,
    pub ref_txs: Vec<BtcRefTx>,
    pub orig_txs: Vec<BtcOrigTx>,
    pub payment_reqs: Vec<BtcPaymentRequest>,
    pub chunkify: bool,
}
