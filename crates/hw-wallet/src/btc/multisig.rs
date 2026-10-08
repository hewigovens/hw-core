use serde::Deserialize;
use trezor_connect::thp::{BtcHDNode, BtcHDNodePath, BtcMultisig, BtcMultisigPubkeysOrder};

use super::hd_node::{TxInputHDNode, TxInputHDNodePath};
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxInputMultisigPubkeysOrder {
    #[serde(alias = "PRESERVED")]
    #[default]
    Preserved,
    #[serde(alias = "LEXICOGRAPHIC")]
    Lexicographic,
}

#[derive(Debug, Deserialize)]
pub struct TxInputMultisig {
    #[serde(default)]
    pub pubkeys: Vec<TxInputHDNodePath>,
    #[serde(default)]
    pub signatures: Vec<String>,
    pub m: u32,
    #[serde(default)]
    pub nodes: Vec<TxInputHDNode>,
    #[serde(default)]
    pub address_n: Vec<u32>,
    #[serde(default)]
    pub pubkeys_order: TxInputMultisigPubkeysOrder,
}

impl From<TxInputMultisigPubkeysOrder> for BtcMultisigPubkeysOrder {
    fn from(order: TxInputMultisigPubkeysOrder) -> Self {
        match order {
            TxInputMultisigPubkeysOrder::Preserved => Self::Preserved,
            TxInputMultisigPubkeysOrder::Lexicographic => Self::Lexicographic,
        }
    }
}

impl TryFrom<TxInputMultisig> for BtcMultisig {
    type Error = WalletError;

    fn try_from(ms: TxInputMultisig) -> WalletResult<Self> {
        if ms.m == 0 {
            return Err(WalletError::Signing(
                "multisig threshold m must be at least 1".into(),
            ));
        }
        let n = if ms.pubkeys.is_empty() {
            ms.nodes.len()
        } else {
            ms.pubkeys.len()
        };
        if n == 0 {
            return Err(WalletError::Signing(
                "multisig requires at least one cosigner (pubkeys or nodes)".into(),
            ));
        }
        if ms.m as usize > n {
            return Err(WalletError::Signing(format!(
                "multisig threshold m={} exceeds number of cosigners n={n}",
                ms.m
            )));
        }

        Ok(Self {
            pubkeys: ms
                .pubkeys
                .into_iter()
                .map(BtcHDNodePath::try_from)
                .collect::<WalletResult<_>>()?,
            signatures: ms
                .signatures
                .iter()
                .map(|sig| decode(sig))
                .collect::<WalletResult<_>>()?,
            m: ms.m,
            nodes: ms
                .nodes
                .iter()
                .map(BtcHDNode::try_from)
                .collect::<WalletResult<_>>()?,
            address_n: ms.address_n,
            pubkeys_order: ms.pubkeys_order.into(),
        })
    }
}
