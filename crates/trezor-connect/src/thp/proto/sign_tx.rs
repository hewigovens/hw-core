use super::bitcoin::BitcoinSignTx;
use super::ethereum::EthereumSignTxEip1559;
use super::solana::SolanaSignTx;
use super::{EncodedMessage, WireMessage};
use crate::thp::types::SignTxRequest;

impl SignTxRequest {
    pub fn encode(&self) -> EncodedMessage {
        match self {
            Self::Ethereum(tx) => EthereumSignTxEip1559::from(tx).to_message(),
            Self::Bitcoin(tx) => BitcoinSignTx::from(tx).to_message(),
            Self::Solana(tx) => SolanaSignTx::from(tx).to_message(),
        }
    }
}
