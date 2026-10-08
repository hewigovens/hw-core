use std::str::FromStr;

pub const DEFAULT_ETHEREUM_BIP32_PATH: &str = "m/44'/60'/0'/0/0";

pub const DEFAULT_BITCOIN_BIP32_PATH: &str = "m/84'/0'/0'/0/0";

pub const DEFAULT_SOLANA_BIP32_PATH: &str = "m/44'/501'/0'/0'";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainConfig {
    pub code: &'static str,
    pub slip44: u32,
    pub default_path: &'static str,
}

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
            Self::Ethereum => ChainConfig {
                code: "eth",
                slip44: 60,
                default_path: DEFAULT_ETHEREUM_BIP32_PATH,
            },
            Self::Bitcoin => ChainConfig {
                code: "btc",
                slip44: 0,
                default_path: DEFAULT_BITCOIN_BIP32_PATH,
            },
            Self::Solana => ChainConfig {
                code: "sol",
                slip44: 501,
                default_path: DEFAULT_SOLANA_BIP32_PATH,
            },
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
        match value.to_ascii_lowercase().as_str() {
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
    fn parse_accepts_codes_and_names_case_insensitively() {
        let cases = [
            ("eth", Chain::Ethereum),
            ("Ethereum", Chain::Ethereum),
            ("BTC", Chain::Bitcoin),
            ("bitcoin", Chain::Bitcoin),
            ("SOL", Chain::Solana),
            ("solana", Chain::Solana),
        ];
        for (input, expected) in cases {
            assert_eq!(input.parse::<Chain>().unwrap(), expected, "{input}");
        }
        assert!("UNKNOWN".parse::<Chain>().is_err());
    }

    #[test]
    fn code_and_slip44_round_trip() {
        for chain in Chain::ALL {
            assert_eq!(chain.as_str().parse::<Chain>().unwrap(), chain);
            assert_eq!(Chain::from_slip44(chain.config().slip44), Some(chain));
        }
        assert_eq!(Chain::from_slip44(999), None);
    }
}
