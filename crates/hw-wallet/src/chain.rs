use crate::WalletResult;
use crate::bip32::parse_bip32_path;
pub use hw_chain::{
    CHAIN_BTC, CHAIN_ETH, CHAIN_SOL, Chain, ChainConfig, DEFAULT_BITCOIN_BIP32_PATH,
    DEFAULT_ETHEREUM_BIP32_PATH, DEFAULT_SOLANA_BIP32_PATH,
};

/// The hardened-key bit (2^31) used when masking coin-type indices.
const HARDENED_MASK: u32 = 0x8000_0000;

/// The fully-resolved derivation path for a signing request.
///
/// Combines the detected or explicit [`Chain`] with the canonical path string
/// and its parsed index vector so callers do not need to re-parse the path.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedDerivationPath {
    /// The blockchain that this path targets.
    pub chain: Chain,
    /// The canonical BIP-32 path string (e.g. `"m/44'/60'/0'/0/0"`).
    pub path: String,
    /// The path parsed into a sequence of 32-bit child-key indices.
    pub path_indices: Vec<u32>,
}

/// Infers the target [`Chain`] from the coin-type component (index 1) of a
/// parsed BIP-32 path.
///
/// Returns `None` if the path has fewer than two components or if the
/// coin type is not recognised.
pub fn infer_chain_from_path(path: &[u32]) -> Option<Chain> {
    let coin_type = path.get(1).copied()? & !HARDENED_MASK;
    Chain::from_slip44(coin_type)
}

/// Resolves a [`ResolvedDerivationPath`] from optional explicit chain and path
/// overrides.
///
/// Resolution rules:
/// 1. If an explicit path is provided it is parsed; the coin type is used to
///    infer the chain.
/// 2. If an explicit chain is also provided it takes precedence, **unless** the
///    inferred chain from the path differs — in that case an error is returned.
/// 3. If neither chain nor path is provided, Ethereum with its default path is
///    used.
///
/// # Errors
///
/// Returns [`WalletError::InvalidBip32Path`] if:
/// - the explicit path cannot be parsed, or
/// - the explicit chain and the chain inferred from the path are different.
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
        && explicit != inferred
    {
        return Err(crate::WalletError::InvalidBip32Path(format!(
            "chain/path mismatch: explicit {explicit:?} conflicts with inferred {inferred:?} from path '{path}'"
        )));
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
            DEFAULT_ETHEREUM_BIP32_PATH
        );
        assert_eq!(Chain::Bitcoin.config().slip44, 0);
        assert_eq!(
            Chain::Bitcoin.config().default_path,
            DEFAULT_BITCOIN_BIP32_PATH
        );
        assert_eq!(Chain::Solana.config().slip44, 501);
        assert_eq!(
            Chain::Solana.config().default_path,
            DEFAULT_SOLANA_BIP32_PATH
        );
    }

    #[test]
    fn infer_chain_from_coin_type() {
        let eth = vec![0x8000_002c, 0x8000_003c];
        let btc = vec![0x8000_002c, 0x8000_0000];
        let sol = vec![0x8000_002c, 0x8000_01f5];

        assert_eq!(infer_chain_from_path(&eth), Some(Chain::Ethereum));
        assert_eq!(infer_chain_from_path(&btc), Some(Chain::Bitcoin));
        assert_eq!(infer_chain_from_path(&sol), Some(Chain::Solana));
    }

    #[test]
    fn resolve_defaults_to_eth_when_empty() {
        let resolved = resolve_derivation_path(None, None).expect("default resolution");
        assert_eq!(resolved.chain, Chain::Ethereum);
        assert_eq!(resolved.path, DEFAULT_ETHEREUM_BIP32_PATH);
    }

    #[test]
    fn resolve_rejects_chain_path_mismatch() {
        let err = resolve_derivation_path(Some(Chain::Bitcoin), Some(DEFAULT_ETHEREUM_BIP32_PATH))
            .expect_err("mismatch should fail");
        assert!(
            err.to_string().contains("chain/path mismatch"),
            "unexpected error: {err}"
        );
    }
}
