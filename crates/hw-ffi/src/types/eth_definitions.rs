use hw_wallet::eth::{DisplayFormatDefinitionInput, TokenDefinitionInput, TxDefinitionsInput};

/// Signed Ethereum definitions (`*.dat` files) the app fetched or bundled; all optional.
#[derive(uniffi::Record, Clone, Debug, Default)]
pub struct EthereumDefinitions {
    #[uniffi(default = None)]
    pub encoded_network: Option<Vec<u8>>,
    #[uniffi(default = None)]
    pub encoded_token: Option<Vec<u8>>,
    #[uniffi(default = None)]
    pub encoded_display_format: Option<Vec<u8>>,
    /// Answered when the device asks for a token mid-signing.
    #[uniffi(default = [])]
    pub tokens: Vec<EthereumTokenDefinition>,
    /// Answered when the device asks for a contract call's display format mid-signing.
    #[uniffi(default = [])]
    pub display_formats: Vec<EthereumDisplayFormatDefinition>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EthereumTokenDefinition {
    /// Hex token contract address.
    pub address: String,
    pub encoded: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct EthereumDisplayFormatDefinition {
    /// Hex contract address.
    pub address: String,
    /// Hex 4-byte function selector.
    pub func_sig: String,
    pub encoded: Vec<u8>,
}

impl From<EthereumDefinitions> for TxDefinitionsInput {
    fn from(definitions: EthereumDefinitions) -> Self {
        Self {
            encoded_network: definitions.encoded_network,
            encoded_token: definitions.encoded_token,
            encoded_display_format: definitions.encoded_display_format,
            tokens: definitions
                .tokens
                .into_iter()
                .map(|token| TokenDefinitionInput {
                    address: token.address,
                    encoded: token.encoded,
                })
                .collect(),
            display_formats: definitions
                .display_formats
                .into_iter()
                .map(|format| DisplayFormatDefinitionInput {
                    address: format.address,
                    func_sig: format.func_sig,
                    encoded: format.encoded,
                })
                .collect(),
        }
    }
}
