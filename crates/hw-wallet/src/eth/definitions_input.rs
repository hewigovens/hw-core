use serde::Deserialize;
use trezor_connect::thp::types::{ETH_ADDRESS_LEN, ETH_FUNC_SIG_LEN};
use trezor_connect::thp::{
    EthDefinitionCatalog, EthDefinitions, EthDisplayFormatDefinition, EthSignTx, EthTokenDefinition,
};

use crate::error::{WalletError, WalletResult};
use crate::hex::decode_fixed;

/// Signed definition blobs the caller already has; JSON carries them as hex.
#[derive(Debug, Default, Deserialize)]
pub struct TxDefinitionsInput {
    #[serde(default, deserialize_with = "crate::hex::deserialize_optional")]
    pub encoded_network: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex::deserialize_optional")]
    pub encoded_token: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "crate::hex::deserialize_optional")]
    pub encoded_display_format: Option<Vec<u8>>,
    /// Returned when the device asks for a token mid-signing.
    #[serde(default)]
    pub tokens: Vec<TokenDefinitionInput>,
    /// Returned when the device asks for a contract call's display format mid-signing.
    #[serde(default)]
    pub display_formats: Vec<DisplayFormatDefinitionInput>,
}

#[derive(Debug, Deserialize)]
pub struct TokenDefinitionInput {
    pub address: String,
    #[serde(deserialize_with = "crate::hex::deserialize")]
    pub encoded: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct DisplayFormatDefinitionInput {
    pub address: String,
    pub func_sig: String,
    #[serde(deserialize_with = "crate::hex::deserialize")]
    pub encoded: Vec<u8>,
}

impl TxDefinitionsInput {
    pub fn apply_to(self, tx: EthSignTx) -> WalletResult<EthSignTx> {
        let catalog = EthDefinitionCatalog {
            tokens: self
                .tokens
                .into_iter()
                .map(EthTokenDefinition::try_from)
                .collect::<WalletResult<_>>()?,
            display_formats: self
                .display_formats
                .into_iter()
                .map(EthDisplayFormatDefinition::try_from)
                .collect::<WalletResult<_>>()?,
        };
        Ok(tx
            .with_definitions(EthDefinitions {
                encoded_network: self.encoded_network,
                encoded_token: self.encoded_token,
                encoded_display_format: self.encoded_display_format,
            })
            .with_definition_catalog(catalog))
    }
}

impl TryFrom<TokenDefinitionInput> for EthTokenDefinition {
    type Error = WalletError;

    fn try_from(input: TokenDefinitionInput) -> WalletResult<Self> {
        Ok(Self {
            address: decode_fixed::<ETH_ADDRESS_LEN>("tokens.address", &input.address)?,
            encoded: input.encoded,
        })
    }
}

impl TryFrom<DisplayFormatDefinitionInput> for EthDisplayFormatDefinition {
    type Error = WalletError;

    fn try_from(input: DisplayFormatDefinitionInput) -> WalletResult<Self> {
        Ok(Self {
            address: decode_fixed::<ETH_ADDRESS_LEN>("display_formats.address", &input.address)?,
            func_sig: decode_fixed::<ETH_FUNC_SIG_LEN>(
                "display_formats.func_sig",
                &input.func_sig,
            )?,
            encoded: input.encoded,
        })
    }
}
