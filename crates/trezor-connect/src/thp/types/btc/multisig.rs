#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcHDNode {
    pub depth: u32,
    pub fingerprint: u32,
    pub child_num: u32,
    pub chain_code: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcHDNodePath {
    pub node: BtcHDNode,
    pub address_n: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcMultisigPubkeysOrder {
    Preserved,
    Lexicographic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcMultisig {
    pub pubkeys: Vec<BtcHDNodePath>,
    pub signatures: Vec<Vec<u8>>,
    pub m: u32,
    pub nodes: Vec<BtcHDNode>,
    pub address_n: Vec<u32>,
    pub pubkeys_order: BtcMultisigPubkeysOrder,
}
