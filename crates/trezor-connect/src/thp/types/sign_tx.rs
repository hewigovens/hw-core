use hw_chain::Chain;

use super::{BtcSignTx, EthSignTx, EthTxSignature, SolanaSignTx};

#[derive(Debug, Clone)]
pub enum SignTxRequest {
    Ethereum(EthSignTx),
    Bitcoin(BtcSignTx),
    Solana(SolanaSignTx),
}

impl SignTxRequest {
    pub fn chain(&self) -> Chain {
        match self {
            Self::Ethereum(_) => Chain::Ethereum,
            Self::Bitcoin(_) => Chain::Bitcoin,
            Self::Solana(_) => Chain::Solana,
        }
    }
}

impl From<EthSignTx> for SignTxRequest {
    fn from(tx: EthSignTx) -> Self {
        Self::Ethereum(tx)
    }
}

impl From<BtcSignTx> for SignTxRequest {
    fn from(tx: BtcSignTx) -> Self {
        Self::Bitcoin(tx)
    }
}

impl From<SolanaSignTx> for SignTxRequest {
    fn from(tx: SolanaSignTx) -> Self {
        Self::Solana(tx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignTxResponse {
    Ethereum(EthTxSignature),
    Bitcoin {
        /// Per-input signatures, indexed by the device's `signature_index`.
        signatures: Vec<Vec<u8>>,
        /// Last indexed signature, or the last unindexed one for legacy firmware.
        last_signature: Vec<u8>,
    },
    Solana {
        signature: Vec<u8>,
    },
}

impl SignTxResponse {
    pub fn chain(&self) -> Chain {
        match self {
            Self::Ethereum(_) => Chain::Ethereum,
            Self::Bitcoin { .. } => Chain::Bitcoin,
            Self::Solana { .. } => Chain::Solana,
        }
    }
}
