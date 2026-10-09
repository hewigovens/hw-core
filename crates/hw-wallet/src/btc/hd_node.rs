use serde::Deserialize;
use sha2::{Digest, Sha256};
use trezor_connect::thp::{BtcHDNode, BtcHDNodePath};

use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

#[derive(Debug, Deserialize)]
pub struct TxInputHDNode {
    pub depth: u32,
    pub fingerprint: u32,
    pub child_num: u32,
    pub chain_code: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TxInputHDNodeRef {
    Node(TxInputHDNode),
    Xpub(String),
}

#[derive(Debug, Deserialize)]
pub struct TxInputHDNodePath {
    pub node: TxInputHDNodeRef,
    pub address_n: Vec<u32>,
}

impl TryFrom<&TxInputHDNode> for BtcHDNode {
    type Error = WalletError;

    fn try_from(node: &TxInputHDNode) -> WalletResult<Self> {
        let chain_code = decode(&node.chain_code)?;
        if chain_code.len() != 32 {
            return Err(WalletError::Signing(format!(
                "invalid hd_node.chain_code length: expected 32 bytes, got {}",
                chain_code.len()
            )));
        }

        let public_key = decode(&node.public_key)?;
        if public_key.len() != 33 {
            return Err(WalletError::Signing(format!(
                "invalid hd_node.public_key length: expected 33 bytes, got {}",
                public_key.len()
            )));
        }

        Ok(Self {
            depth: node.depth,
            fingerprint: node.fingerprint,
            child_num: node.child_num,
            chain_code,
            public_key,
        })
    }
}

impl TryFrom<&TxInputHDNodeRef> for BtcHDNode {
    type Error = WalletError;

    fn try_from(node: &TxInputHDNodeRef) -> WalletResult<Self> {
        match node {
            TxInputHDNodeRef::Node(node) => Self::try_from(node),
            TxInputHDNodeRef::Xpub(xpub) => hd_node_from_xpub(xpub),
        }
    }
}

impl TryFrom<TxInputHDNodePath> for BtcHDNodePath {
    type Error = WalletError;

    fn try_from(path: TxInputHDNodePath) -> WalletResult<Self> {
        Ok(Self {
            node: BtcHDNode::try_from(&path.node)?,
            address_n: path.address_n,
        })
    }
}

fn hd_node_from_xpub(xpub: &str) -> WalletResult<BtcHDNode> {
    let invalid = |reason: String| WalletError::Signing(format!("invalid xpub '{xpub}': {reason}"));
    let decoded = bs58::decode(xpub)
        .into_vec()
        .map_err(|err| invalid(err.to_string()))?;
    if decoded.len() < 4 {
        return Err(invalid("payload is too short".into()));
    }

    let (payload, checksum) = decoded.split_at(decoded.len() - 4);
    let expected_checksum = Sha256::digest(Sha256::digest(payload));
    if checksum != &expected_checksum[..4] {
        return Err(invalid("checksum mismatch".into()));
    }
    let Ok(payload) = <&[u8; 78]>::try_from(payload) else {
        return Err(invalid(format!(
            "expected 78-byte payload, got {} bytes",
            payload.len()
        )));
    };

    let key_prefix = payload[45];
    if key_prefix != 0x02 && key_prefix != 0x03 {
        return Err(invalid(
            "compressed public key must start with 0x02 or 0x03".into(),
        ));
    }

    let [_, _, _, _, depth, f0, f1, f2, f3, c0, c1, c2, c3, ..] = *payload;
    Ok(BtcHDNode {
        depth: u32::from(depth),
        fingerprint: u32::from_be_bytes([f0, f1, f2, f3]),
        child_num: u32::from_be_bytes([c0, c1, c2, c3]),
        chain_code: payload[13..45].to_vec(),
        public_key: payload[45..78].to_vec(),
    })
}
