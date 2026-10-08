use trezor_connect::thp::Chain as RawChain;

pub type Chain = RawChain;

#[uniffi::remote(Enum)]
pub enum Chain {
    Ethereum,
    Bitcoin,
    Solana,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ChainConfig {
    pub code: String,
    pub slip44: u32,
    pub default_path: String,
}

impl From<Chain> for ChainConfig {
    fn from(chain: Chain) -> Self {
        let raw = chain.config();
        Self {
            code: raw.code.to_string(),
            slip44: raw.slip44,
            default_path: raw.default_path.to_string(),
        }
    }
}

#[uniffi::export]
pub fn chain_config(chain: Chain) -> ChainConfig {
    chain.into()
}
