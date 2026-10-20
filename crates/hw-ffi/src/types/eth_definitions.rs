use std::sync::Arc;

use hw_wallet::eth::{DisplayFormatDefinitionInput, TokenDefinitionInput, TxDefinitionsInput};
use hw_wallet::hex::decode_fixed;
use trezor_connect::thp::EthDefinitionsVersion;
use trezor_connect::thp::types::{ETH_ADDRESS_LEN, ETH_FUNC_SIG_LEN};

use super::{Chain, DeviceFeatures};
use crate::errors::HWCoreError;

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

/// Network definitions only exist for Ethereum; reject them for other chains instead of dropping them.
pub(crate) fn ethereum_encoded_network(
    chain: Chain,
    encoded_network: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, HWCoreError> {
    match (chain, encoded_network) {
        (Chain::Bitcoin | Chain::Solana, Some(_)) => Err(HWCoreError::Validation(format!(
            "encoded_network is only supported for Ethereum, not {chain:?}"
        ))),
        (Chain::Ethereum | Chain::Bitcoin | Chain::Solana, encoded_network) => Ok(encoded_network),
    }
}

/// Where to download definitions for a device, mirroring Trezor Suite's data.trezor.io layout.
#[derive(uniffi::Object, Debug)]
pub struct EthereumDefinitionsSource {
    version: EthDefinitionsVersion,
}

#[uniffi::export]
impl EthereumDefinitionsSource {
    /// Picks the definitions format the firmware in `features` accepts.
    #[uniffi::constructor]
    pub fn for_firmware(features: DeviceFeatures) -> Arc<Self> {
        Arc::new(Self {
            version: EthDefinitionsVersion::for_firmware(&features),
        })
    }

    /// Definitions format version: 1 or 2.
    pub fn version(&self) -> u32 {
        match self.version {
            EthDefinitionsVersion::V1 => 1,
            EthDefinitionsVersion::V2 => 2,
        }
    }

    pub fn network_url(&self, chain_id: u64) -> String {
        self.version.network_url(chain_id)
    }

    pub fn network_url_for_slip44(&self, slip44: u32) -> String {
        self.version.network_url_for_slip44(slip44)
    }

    pub fn token_url(&self, chain_id: u64, address: String) -> Result<String, HWCoreError> {
        let address = decode_fixed::<ETH_ADDRESS_LEN>("address", &address)?;
        Ok(self.version.token_url(chain_id, &address))
    }

    pub fn display_format_url(
        &self,
        chain_id: u64,
        address: String,
        func_sig: String,
    ) -> Result<String, HWCoreError> {
        let address = decode_fixed::<ETH_ADDRESS_LEN>("address", &address)?;
        let func_sig = decode_fixed::<ETH_FUNC_SIG_LEN>("func_sig", &func_sig)?;
        Ok(self
            .version
            .display_format_url(chain_id, &address, &func_sig))
    }
}
