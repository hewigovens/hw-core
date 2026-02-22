use std::str::FromStr;

/// Default BIP-32 derivation path for Ethereum accounts (EIP-44, coin type 60).
pub const DEFAULT_ETHEREUM_BIP32_PATH: &str = "m/44'/60'/0'/0/0";

/// Default BIP-32 derivation path for Bitcoin accounts using BIP-84 (native SegWit, coin type 0).
pub const DEFAULT_BITCOIN_BIP32_PATH: &str = "m/84'/0'/0'/0/0";

/// Default BIP-32 derivation path for Solana accounts (coin type 501).
pub const DEFAULT_SOLANA_BIP32_PATH: &str = "m/44'/501'/0'/0'";

/// Short identifier string for the Ethereum chain (`"eth"`).
pub const CHAIN_ETH: &str = "eth";

/// Short identifier string for the Bitcoin chain (`"btc"`).
pub const CHAIN_BTC: &str = "btc";

/// Short identifier string for the Solana chain (`"sol"`).
pub const CHAIN_SOL: &str = "sol";

/// Static configuration for a supported blockchain.
///
/// Bundles the short chain code, SLIP-44 coin type, and the default BIP-32
/// derivation path used when the caller does not supply an explicit path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainConfig {
    /// Short lowercase code used in CLI flags and configuration (e.g. `"eth"`).
    pub code: &'static str,
    /// [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) coin-type index.
    pub slip44: u32,
    /// Default BIP-32 derivation path string (e.g. `"m/44'/60'/0'/0/0"`).
    pub default_path: &'static str,
}

/// Pre-built [`ChainConfig`] for Ethereum / EVM-compatible chains.
pub const ETHEREUM_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_ETH,
    slip44: 60,
    default_path: DEFAULT_ETHEREUM_BIP32_PATH,
};

/// Pre-built [`ChainConfig`] for Bitcoin (native SegWit / BIP-84).
pub const BITCOIN_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_BTC,
    slip44: 0,
    default_path: DEFAULT_BITCOIN_BIP32_PATH,
};

/// Pre-built [`ChainConfig`] for Solana.
pub const SOLANA_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_SOL,
    slip44: 501,
    default_path: DEFAULT_SOLANA_BIP32_PATH,
};

/// A blockchain supported by the hw-core library.
///
/// Use [`Chain::config`] to retrieve the associated [`ChainConfig`] (SLIP-44
/// coin type, default derivation path, etc.).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chain {
    /// Ethereum and EVM-compatible networks.
    Ethereum,
    /// Bitcoin (native SegWit / BIP-84).
    Bitcoin,
    /// Solana.
    Solana,
}

impl Chain {
    /// All supported chains in a fixed-size array, useful for iteration.
    pub const ALL: [Self; 3] = [Self::Ethereum, Self::Bitcoin, Self::Solana];

    /// Returns the static [`ChainConfig`] for this chain.
    pub const fn config(self) -> ChainConfig {
        match self {
            Self::Ethereum => ETHEREUM_CONFIG,
            Self::Bitcoin => BITCOIN_CONFIG,
            Self::Solana => SOLANA_CONFIG,
        }
    }

    /// Returns the default BIP-32 derivation path string for this chain.
    pub fn default_path(self) -> &'static str {
        self.config().default_path
    }

    /// Returns the short lowercase chain identifier (e.g. `"eth"`, `"btc"`, `"sol"`).
    pub fn as_str(self) -> &'static str {
        self.config().code
    }

    /// Returns the [`Chain`] whose SLIP-44 coin type matches `slip44`, or
    /// `None` if the coin type is not recognised.
    pub fn from_slip44(slip44: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|chain| chain.config().slip44 == slip44)
    }
}

impl FromStr for Chain {
    type Err = String;

    /// Parses a chain from a string.
    ///
    /// Accepted values (case-sensitive):
    /// - `"eth"` or `"ethereum"` → [`Chain::Ethereum`]
    /// - `"btc"` or `"bitcoin"`  → [`Chain::Bitcoin`]
    /// - `"sol"` or `"solana"`   → [`Chain::Solana`]
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "eth" | "ethereum" => Ok(Self::Ethereum),
            "btc" | "bitcoin" => Ok(Self::Bitcoin),
            "sol" | "solana" => Ok(Self::Solana),
            _ => Err(format!(
                "unsupported chain '{value}'; expected eth, btc, or sol"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_values() {
        assert_eq!(Chain::Ethereum.config().slip44, 60);
        assert_eq!(Chain::Ethereum.default_path(), DEFAULT_ETHEREUM_BIP32_PATH);
        assert_eq!(Chain::Bitcoin.config().slip44, 0);
        assert_eq!(Chain::Bitcoin.default_path(), DEFAULT_BITCOIN_BIP32_PATH);
        assert_eq!(Chain::Solana.config().slip44, 501);
        assert_eq!(Chain::Solana.default_path(), DEFAULT_SOLANA_BIP32_PATH);
    }

    #[test]
    fn parse_chain_aliases() {
        assert_eq!("eth".parse::<Chain>().unwrap(), Chain::Ethereum);
        assert_eq!("ethereum".parse::<Chain>().unwrap(), Chain::Ethereum);
        assert_eq!("btc".parse::<Chain>().unwrap(), Chain::Bitcoin);
        assert_eq!("bitcoin".parse::<Chain>().unwrap(), Chain::Bitcoin);
        assert_eq!("sol".parse::<Chain>().unwrap(), Chain::Solana);
        assert_eq!("solana".parse::<Chain>().unwrap(), Chain::Solana);
    }

    #[test]
    fn from_slip44_works() {
        assert_eq!(Chain::from_slip44(60), Some(Chain::Ethereum));
        assert_eq!(Chain::from_slip44(0), Some(Chain::Bitcoin));
        assert_eq!(Chain::from_slip44(501), Some(Chain::Solana));
        assert_eq!(Chain::from_slip44(999), None);
    }
}
