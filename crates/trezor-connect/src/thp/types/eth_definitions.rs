pub const ETH_ADDRESS_LEN: usize = 20;
pub const ETH_FUNC_SIG_LEN: usize = 4;

/// Signed Ethereum definitions (`*.dat` blobs from data.trezor.io), forwarded to the firmware as-is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EthDefinitions {
    pub encoded_network: Option<Vec<u8>>,
    pub encoded_token: Option<Vec<u8>>,
    /// ERC-7730 clear-signing display format for the called contract function.
    pub encoded_display_format: Option<Vec<u8>>,
}

impl EthDefinitions {
    pub fn is_empty(&self) -> bool {
        self.encoded_network.is_none()
            && self.encoded_token.is_none()
            && self.encoded_display_format.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthTokenDefinition {
    pub address: [u8; ETH_ADDRESS_LEN],
    pub encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthDisplayFormatDefinition {
    pub address: [u8; ETH_ADDRESS_LEN],
    pub func_sig: [u8; ETH_FUNC_SIG_LEN],
    pub encoded: Vec<u8>,
}

/// Definitions the host can return when the firmware asks for one mid-signing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EthDefinitionCatalog {
    pub tokens: Vec<EthTokenDefinition>,
    pub display_formats: Vec<EthDisplayFormatDefinition>,
}

impl EthDefinitionCatalog {
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty() && self.display_formats.is_empty()
    }

    pub fn token(&self, address: &[u8]) -> Option<&EthTokenDefinition> {
        self.tokens
            .iter()
            .find(|token| token.address.as_slice() == address)
    }

    pub fn display_format(
        &self,
        address: &[u8],
        func_sig: &[u8],
    ) -> Option<&EthDisplayFormatDefinition> {
        self.display_formats.iter().find(|format| {
            format.address.as_slice() == address && format.func_sig.as_slice() == func_sig
        })
    }
}
