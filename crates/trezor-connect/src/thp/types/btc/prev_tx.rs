use super::{BtcSignInput, BtcSignOutput};

#[derive(Debug, Clone)]
pub struct BtcRefTxInput {
    pub prev_hash: Vec<u8>,
    pub prev_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct BtcRefTxOutput {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BtcRefTx {
    pub hash: Vec<u8>,
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<BtcRefTxInput>,
    pub bin_outputs: Vec<BtcRefTxOutput>,
    pub extra_data: Option<Vec<u8>>,
    pub timestamp: Option<u32>,
    pub version_group_id: Option<u32>,
    pub expiry: Option<u32>,
    pub branch_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct BtcOrigTx {
    pub hash: Vec<u8>,
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<BtcSignInput>,
    pub outputs: Vec<BtcSignOutput>,
    pub extra_data: Option<Vec<u8>>,
    pub timestamp: Option<u32>,
    pub version_group_id: Option<u32>,
    pub expiry: Option<u32>,
    pub branch_id: Option<u32>,
}
