use prost::Message;

use crate::thp::proto::wire::wire_messages;
use crate::thp::types::{EthDefinitions, EthSignTx};

#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumDefinitions {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub(crate) encoded_network: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub(crate) encoded_token: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub(crate) encoded_display_format: Option<Vec<u8>>,
}

/// Firmware asks for the token at `token_address`, or the display format of `func_sig` on it.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumDefinitionRequest {
    #[prost(uint64, required, tag = "1")]
    pub(crate) chain_id: u64,
    #[prost(bytes = "vec", required, tag = "2")]
    pub(crate) token_address: Vec<u8>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub(crate) func_sig: Option<Vec<u8>>,
}

/// `definitions` stays unset when the host has nothing matching the request.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct EthereumDefinitionAck {
    #[prost(message, optional, tag = "1")]
    pub(crate) definitions: Option<EthereumDefinitions>,
}

wire_messages! {
    EthereumDefinitionRequest = 471,
    EthereumDefinitionAck = 472,
}

impl EthereumDefinitions {
    /// `None` for empty definitions so requests without any stay byte-identical on the wire.
    pub(crate) fn from_definitions(definitions: &EthDefinitions) -> Option<Self> {
        (!definitions.is_empty()).then(|| Self {
            encoded_network: definitions.encoded_network.clone(),
            encoded_token: definitions.encoded_token.clone(),
            encoded_display_format: definitions.encoded_display_format.clone(),
        })
    }
}

impl EthereumDefinitionAck {
    /// Mirrors Suite: the transaction's network plus the requested token and display format.
    pub fn answer(tx: &EthSignTx, request: &EthereumDefinitionRequest) -> Self {
        if request.chain_id != tx.chain_id {
            return Self { definitions: None };
        }
        let catalog = &tx.definition_catalog;
        let encoded_token = catalog
            .token(&request.token_address)
            .map(|token| token.encoded.clone());
        let encoded_display_format = request.func_sig.as_ref().and_then(|func_sig| {
            catalog
                .display_format(&request.token_address, func_sig)
                .map(|format| format.encoded.clone())
        });
        if encoded_token.is_none() && encoded_display_format.is_none() {
            return Self { definitions: None };
        }
        Self {
            definitions: Some(EthereumDefinitions {
                encoded_network: tx.definitions.encoded_network.clone(),
                encoded_token,
                encoded_display_format,
            }),
        }
    }
}
