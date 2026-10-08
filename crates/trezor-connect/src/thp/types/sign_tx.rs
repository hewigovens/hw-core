use hw_chain::Chain;

use super::{BtcSignTx, EthSignTx, SolanaSignTx};

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

#[derive(Debug, Clone)]
pub struct SignTxResponse {
    pub chain: Chain,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    /// Per-input Bitcoin signatures, indexed by the device's `signature_index`.
    pub signatures: Vec<Vec<u8>>,
}
