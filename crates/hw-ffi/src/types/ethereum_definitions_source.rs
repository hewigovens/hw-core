use std::sync::Arc;

use hw_wallet::hex::decode_fixed;
use trezor_connect::thp::EthDefinitionsVersion;
use trezor_connect::thp::types::{ETH_ADDRESS_LEN, ETH_FUNC_SIG_LEN};

use super::DeviceFeatures;
use crate::errors::HWCoreError;

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
