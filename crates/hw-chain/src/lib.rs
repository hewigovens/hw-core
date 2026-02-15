use std::str::FromStr;

pub const DEFAULT_ETHEREUM_BIP32_PATH: &str = "m/44'/60'/0'/0/0";
pub const DEFAULT_BITCOIN_BIP32_PATH: &str = "m/84'/0'/0'/0/0";
pub const DEFAULT_SOLANA_BIP32_PATH: &str = "m/44'/501'/0'/0'";
pub const CHAIN_ETH: &str = "eth";
pub const CHAIN_BTC: &str = "btc";
pub const CHAIN_SOL: &str = "sol";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainConfig {
    pub code: &'static str,
    pub slip44: u32,
    pub default_path: &'static str,
}

pub const ETHEREUM_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_ETH,
    slip44: 60,
    default_path: DEFAULT_ETHEREUM_BIP32_PATH,
};

pub const BITCOIN_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_BTC,
    slip44: 0,
    default_path: DEFAULT_BITCOIN_BIP32_PATH,
};

pub const SOLANA_CONFIG: ChainConfig = ChainConfig {
    code: CHAIN_SOL,
    slip44: 501,
    default_path: DEFAULT_SOLANA_BIP32_PATH,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chain {
    Ethereum,
    Bitcoin,
    Solana,
}

impl Chain {
    pub const ALL: [Self; 3] = [Self::Ethereum, Self::Bitcoin, Self::Solana];

    pub const fn config(self) -> ChainConfig {
        match self {
            Self::Ethereum => ETHEREUM_CONFIG,
            Self::Bitcoin => BITCOIN_CONFIG,
            Self::Solana => SOLANA_CONFIG,
        }
    }

    pub fn default_path(self) -> &'static str {
        self.config().default_path
    }

    pub fn as_str(self) -> &'static str {
        self.config().code
    }

    pub fn from_slip44(slip44: u32) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|chain| chain.config().slip44 == slip44)
    }
}

impl FromStr for Chain {
    type Err = String;

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
