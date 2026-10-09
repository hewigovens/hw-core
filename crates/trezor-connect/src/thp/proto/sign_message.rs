use hw_chain::Chain;

use super::bitcoin::{BitcoinMessageSignature, BitcoinSignMessage};
use super::ethereum::{EthereumMessageSignature, EthereumSignMessage};
use super::solana::{SolanaMessageSignature, SolanaSignMessage};
use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::types::{SignMessageRequest, SignMessageResponse};

impl SignMessageRequest {
    pub fn encode(&self) -> Result<EncodedMessage, ProtoMappingError> {
        Ok(match self.chain {
            Chain::Bitcoin => BitcoinSignMessage::from(self).to_message(),
            Chain::Ethereum => EthereumSignMessage::from(self).to_message(),
            Chain::Solana => SolanaSignMessage::try_from(self)?.to_message(),
        })
    }
}

impl SignMessageResponse {
    pub fn decode(
        chain: Chain,
        message_type: u16,
        payload: &[u8],
    ) -> Result<Self, ProtoMappingError> {
        Ok(match chain {
            Chain::Bitcoin => BitcoinMessageSignature::from_message(message_type, payload)?.into(),
            Chain::Ethereum => {
                EthereumMessageSignature::from_message(message_type, payload)?.into()
            }
            Chain::Solana => SolanaMessageSignature::from_message(message_type, payload)?.into(),
        })
    }
}
