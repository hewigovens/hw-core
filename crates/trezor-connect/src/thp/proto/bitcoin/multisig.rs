use prost::Message;

use crate::thp::types::{BtcHDNode, BtcHDNodePath, BtcMultisig, BtcMultisigPubkeysOrder};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct HDNodeTypeProto {
    #[prost(uint32, required, tag = "1")]
    pub(crate) depth: u32,
    #[prost(uint32, required, tag = "2")]
    pub(crate) fingerprint: u32,
    #[prost(uint32, required, tag = "3")]
    pub(crate) child_num: u32,
    #[prost(bytes = "vec", required, tag = "4")]
    pub(crate) chain_code: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub(crate) private_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", required, tag = "6")]
    pub(crate) public_key: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct HDNodePathTypeProto {
    #[prost(message, required, tag = "1")]
    pub(crate) node: HDNodeTypeProto,
    #[prost(uint32, repeated, packed = "false", tag = "2")]
    pub(crate) address_n: Vec<u32>,
}

#[derive(Clone, PartialEq, Message)]
pub(crate) struct MultisigRedeemScriptTypeProto {
    #[prost(message, repeated, tag = "1")]
    pub(crate) pubkeys: Vec<HDNodePathTypeProto>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub(crate) signatures: Vec<Vec<u8>>,
    #[prost(uint32, required, tag = "3")]
    pub(crate) m: u32,
    #[prost(message, repeated, tag = "4")]
    pub(crate) nodes: Vec<HDNodeTypeProto>,
    #[prost(uint32, repeated, packed = "false", tag = "5")]
    pub(crate) address_n: Vec<u32>,
    #[prost(enumeration = "MultisigPubkeysOrderProto", optional, tag = "6")]
    pub(crate) pubkeys_order: Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub(crate) enum MultisigPubkeysOrderProto {
    Preserved = 0,
    Lexicographic = 1,
}

impl From<&BtcHDNode> for HDNodeTypeProto {
    fn from(node: &BtcHDNode) -> Self {
        Self {
            depth: node.depth,
            fingerprint: node.fingerprint,
            child_num: node.child_num,
            chain_code: node.chain_code.clone(),
            private_key: None,
            public_key: node.public_key.clone(),
        }
    }
}

impl From<&BtcHDNodePath> for HDNodePathTypeProto {
    fn from(entry: &BtcHDNodePath) -> Self {
        Self {
            node: (&entry.node).into(),
            address_n: entry.address_n.clone(),
        }
    }
}

impl From<BtcMultisigPubkeysOrder> for MultisigPubkeysOrderProto {
    fn from(order: BtcMultisigPubkeysOrder) -> Self {
        match order {
            BtcMultisigPubkeysOrder::Preserved => Self::Preserved,
            BtcMultisigPubkeysOrder::Lexicographic => Self::Lexicographic,
        }
    }
}

impl From<&BtcMultisig> for MultisigRedeemScriptTypeProto {
    fn from(multisig: &BtcMultisig) -> Self {
        Self {
            pubkeys: multisig.pubkeys.iter().map(Into::into).collect(),
            signatures: multisig.signatures.clone(),
            m: multisig.m,
            nodes: multisig.nodes.iter().map(Into::into).collect(),
            address_n: multisig.address_n.clone(),
            pubkeys_order: Some(MultisigPubkeysOrderProto::from(multisig.pubkeys_order) as i32),
        }
    }
}
