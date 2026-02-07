use crate::bip32::parse_bip32_path;
use crate::WalletResult;
pub use hw_chain::{
    Chain, ChainConfig, CHAIN_BTC, CHAIN_ETH, DEFAULT_BITCOIN_BIP32_PATH,
    DEFAULT_ETHEREUM_BIP32_PATH,
};

pub const DEFAULT_ETH_BIP32_PATH: &str = DEFAULT_ETHEREUM_BIP32_PATH;
pub const DEFAULT_BTC_BIP32_PATH: &str = DEFAULT_BITCOIN_BIP32_PATH;

const HARDENED_MASK: u32 = 0x8000_0000;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedDerivationPath {
    pub chain: Chain,
    pub path: String,
    pub path_indices: Vec<u32>,
}

pub fn infer_chain_from_path(path: &[u32]) -> Option<Chain> {
    let coin_type = path.get(1).copied()? & !HARDENED_MASK;
    Chain::from_slip44(coin_type)
}

pub fn resolve_derivation_path(
    explicit_chain: Option<Chain>,
    explicit_path: Option<&str>,
) -> WalletResult<ResolvedDerivationPath> {
    let parsed_path = explicit_path
        .map(|path| parse_bip32_path(path).map(|indices| (path.to_owned(), indices)))
        .transpose()?;

    let inferred_chain = parsed_path
        .as_ref()
        .and_then(|(_, indices)| infer_chain_from_path(indices));
    let chain = explicit_chain.or(inferred_chain).unwrap_or(Chain::Ethereum);

    if let (Some(explicit), Some(inferred), Some(path)) =
        (explicit_chain, inferred_chain, explicit_path)
    {
        if explicit != inferred {
            return Err(crate::WalletError::InvalidBip32Path(format!(
                "chain/path mismatch: explicit {explicit:?} conflicts with inferred {inferred:?} from path '{path}'"
            )));
        }
    }

    let (path, path_indices) = if let Some((path, path_indices)) = parsed_path {
        (path, path_indices)
    } else {
        let default_path = chain.default_path().to_owned();
        let path_indices = parse_bip32_path(&default_path)?;
        (default_path, path_indices)
    };

    Ok(ResolvedDerivationPath {
        chain,
        path,
        path_indices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_config_values() {
        assert_eq!(Chain::Ethereum.config().slip44, 60);
        assert_eq!(
            Chain::Ethereum.config().default_path,
            DEFAULT_ETH_BIP32_PATH
        );
        assert_eq!(Chain::Bitcoin.config().slip44, 0);
        assert_eq!(Chain::Bitcoin.config().default_path, DEFAULT_BTC_BIP32_PATH);
    }

    #[test]
    fn infer_chain_from_coin_type() {
        let eth = vec![0x8000_002c, 0x8000_003c];
        let btc = vec![0x8000_002c, 0x8000_0000];

        assert_eq!(infer_chain_from_path(&eth), Some(Chain::Ethereum));
        assert_eq!(infer_chain_from_path(&btc), Some(Chain::Bitcoin));
    }

    #[test]
    fn resolve_defaults_to_eth_when_empty() {
        let resolved = resolve_derivation_path(None, None).expect("default resolution");
        assert_eq!(resolved.chain, Chain::Ethereum);
        assert_eq!(resolved.path, DEFAULT_ETH_BIP32_PATH);
    }

    #[test]
    fn resolve_rejects_chain_path_mismatch() {
        let err = resolve_derivation_path(Some(Chain::Bitcoin), Some(DEFAULT_ETH_BIP32_PATH))
            .expect_err("mismatch should fail");
        assert!(
            err.to_string().contains("chain/path mismatch"),
            "unexpected error: {err}"
        );
    }
}
