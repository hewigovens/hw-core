use hw_chain::Chain;

use super::bitcoin::{BitcoinAddress, BitcoinGetAddress, BitcoinGetPublicKey, BitcoinPublicKey};
use super::ethereum::{
    EthereumAddress, EthereumGetAddress, EthereumGetPublicKey, EthereumPublicKey,
};
use super::solana::{SolanaAddress, SolanaGetAddress, SolanaGetPublicKey, SolanaPublicKey};
use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::types::{GetAddressRequest, GetAddressResponse, GetPublicKeyRequest};

impl GetAddressRequest {
    pub fn encode(&self) -> EncodedMessage {
        match self.chain {
            Chain::Ethereum => EthereumGetAddress::from(self).to_message(),
            Chain::Bitcoin => BitcoinGetAddress::from(self).to_message(),
            Chain::Solana => SolanaGetAddress::from(self).to_message(),
        }
    }
}

impl GetAddressResponse {
    pub fn decode(
        chain: Chain,
        message_type: u16,
        payload: &[u8],
    ) -> Result<Self, ProtoMappingError> {
        match chain {
            Chain::Ethereum => EthereumAddress::from_message(message_type, payload)?.try_into(),
            Chain::Bitcoin => Ok(BitcoinAddress::from_message(message_type, payload)?.into()),
            Chain::Solana => Ok(SolanaAddress::from_message(message_type, payload)?.into()),
        }
    }
}

impl GetPublicKeyRequest {
    pub fn encode(&self) -> EncodedMessage {
        match self.chain {
            Chain::Ethereum => EthereumGetPublicKey::from(self).to_message(),
            Chain::Bitcoin => BitcoinGetPublicKey::from(self).to_message(),
            Chain::Solana => SolanaGetPublicKey::from(self).to_message(),
        }
    }

    /// Decodes the reply into the chain's public key format: an xpub, or base58 on Solana.
    pub fn decode_response(
        &self,
        message_type: u16,
        payload: &[u8],
    ) -> Result<String, ProtoMappingError> {
        match self.chain {
            Chain::Ethereum => EthereumPublicKey::from_message(message_type, payload)?
                .xpub
                .ok_or(ProtoMappingError::UnexpectedMessage(message_type)),
            Chain::Bitcoin => Ok(BitcoinPublicKey::from_message(message_type, payload)?.xpub),
            Chain::Solana => {
                let message = SolanaPublicKey::from_message(message_type, payload)?;
                Ok(bs58::encode(message.public_key).into_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoders_reject_another_chains_message_type() {
        let ethereum_address = EthereumAddress::MESSAGE_TYPE;
        for chain in [Chain::Bitcoin, Chain::Solana] {
            assert!(matches!(
                GetAddressResponse::decode(chain, ethereum_address, &[]),
                Err(ProtoMappingError::UnexpectedMessage(57))
            ));
        }
        let request = GetPublicKeyRequest::new(Chain::Ethereum, Vec::new());
        assert!(matches!(
            request.decode_response(BitcoinPublicKey::MESSAGE_TYPE, &[]),
            Err(ProtoMappingError::UnexpectedMessage(12))
        ));
    }
}
