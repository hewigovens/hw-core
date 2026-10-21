use super::{DeviceFeatures, ETH_ADDRESS_LEN, ETH_FUNC_SIG_LEN};

const PRODUCTION_DEFINITIONS_URL: &str = "https://data.trezor.io/firmware/definitions";

/// Signed-definitions format a firmware accepts (v1: two signatures, v2: one), with Suite's URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthDefinitionsVersion {
    V1,
    V2,
}

impl EthDefinitionsVersion {
    /// Mirrors Suite: Core accepts v2 since 2.13.0, Legacy only accepts v2 since 1.14.2.
    pub fn for_firmware(features: &DeviceFeatures) -> Self {
        let v2_supported = match features.major_version {
            1 => features.version_at_least(1, 14, 2),
            2 => features.version_at_least(2, 13, 0),
            _ => false,
        };
        if v2_supported { Self::V2 } else { Self::V1 }
    }

    /// Base URL of the Ethereum definitions; production serves v1 from the unversioned path.
    pub fn eth_base_url(self) -> String {
        match self {
            Self::V1 => format!("{PRODUCTION_DEFINITIONS_URL}/eth"),
            Self::V2 => format!("{PRODUCTION_DEFINITIONS_URL}/v2/eth"),
        }
    }

    pub fn network_url(self, chain_id: u64) -> String {
        format!("{}/chain-id/{chain_id}/network.dat", self.eth_base_url())
    }

    /// Network lookup by SLIP-44 coin type, for requests without a chain id (e.g. get address).
    pub fn network_url_for_slip44(self, slip44: u32) -> String {
        format!("{}/slip44/{slip44}/network.dat", self.eth_base_url())
    }

    pub fn token_url(self, chain_id: u64, address: &[u8; ETH_ADDRESS_LEN]) -> String {
        format!(
            "{}/chain-id/{chain_id}/token-{}.dat",
            self.eth_base_url(),
            hex::encode(address)
        )
    }

    pub fn display_format_url(
        self,
        chain_id: u64,
        address: &[u8; ETH_ADDRESS_LEN],
        func_sig: &[u8; ETH_FUNC_SIG_LEN],
    ) -> String {
        format!(
            "{}/chain-id/{chain_id}/display-format/{}-{}.dat",
            self.eth_base_url(),
            hex::encode(address),
            hex::encode(func_sig)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(major_version: u32, minor_version: u32, patch_version: u32) -> DeviceFeatures {
        DeviceFeatures {
            major_version,
            minor_version,
            patch_version,
            ..DeviceFeatures::default()
        }
    }

    #[test]
    fn selects_v2_from_suite_minimum_firmware() {
        use EthDefinitionsVersion::{V1, V2};
        for (version, expected) in [
            ((1, 14, 1), V1),
            ((1, 14, 2), V2),
            ((2, 12, 9), V1),
            ((2, 13, 0), V2),
            ((2, 14, 0), V2),
            ((0, 0, 0), V1),
        ] {
            let (major, minor, patch) = version;
            assert_eq!(
                EthDefinitionsVersion::for_firmware(&features(major, minor, patch)),
                expected,
                "firmware {major}.{minor}.{patch}"
            );
        }
    }

    #[test]
    fn builds_suite_definition_urls() {
        let usdt: [u8; ETH_ADDRESS_LEN] = hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            EthDefinitionsVersion::V1.network_url(1),
            "https://data.trezor.io/firmware/definitions/eth/chain-id/1/network.dat"
        );
        assert_eq!(
            EthDefinitionsVersion::V2.network_url_for_slip44(60),
            "https://data.trezor.io/firmware/definitions/v2/eth/slip44/60/network.dat"
        );
        assert_eq!(
            EthDefinitionsVersion::V2.token_url(1, &usdt),
            "https://data.trezor.io/firmware/definitions/v2/eth/chain-id/1/token-dac17f958d2ee523a2206206994597c13d831ec7.dat"
        );
        assert_eq!(
            EthDefinitionsVersion::V2.display_format_url(1, &usdt, &[0xa9, 0x05, 0x9c, 0xbb]),
            "https://data.trezor.io/firmware/definitions/v2/eth/chain-id/1/display-format/dac17f958d2ee523a2206206994597c13d831ec7-a9059cbb.dat"
        );
    }
}
