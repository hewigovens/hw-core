use hw_chain::Chain;

use super::bitcoin::BitcoinSignTx;
use super::ethereum::EthereumSignTxEip1559;
use super::solana::SolanaSignTx;
use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::types::SignTxRequest;

impl SignTxRequest {
    /// Returns the sign request and how many bytes of `data` it already carries.
    pub fn encode(&self) -> Result<(EncodedMessage, usize), ProtoMappingError> {
        Ok(match self.chain {
            Chain::Ethereum => (
                EthereumSignTxEip1559::from(self).to_message(),
                EthereumSignTxEip1559::initial_chunk_len(self),
            ),
            Chain::Bitcoin => (BitcoinSignTx::try_from(self)?.to_message(), 0),
            Chain::Solana => (SolanaSignTx::from(self).to_message(), 0),
        })
    }
}
