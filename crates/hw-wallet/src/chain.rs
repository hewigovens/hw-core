pub use hw_chain::{
    Chain, ChainConfig, DEFAULT_BITCOIN_BIP32_PATH, DEFAULT_ETHEREUM_BIP32_PATH,
    DEFAULT_SOLANA_BIP32_PATH,
};

use crate::bip32::{HARDENED, parse_bip32_path};
use crate::error::{WalletError, WalletResult};

pub trait ChainPathExt: Sized {
    fn from_bip32_path(path: &[u32]) -> Option<Self>;
    fn validate_signing_path(self, path: &[u32], operation: &str) -> WalletResult<()>;
}

impl ChainPathExt for Chain {
    fn from_bip32_path(path: &[u32]) -> Option<Self> {
        let coin_type = path.get(1).copied()? & !HARDENED;
        Self::from_slip44(coin_type)
    }

    fn validate_signing_path(self, path: &[u32], operation: &str) -> WalletResult<()> {
        // Firmware accepts the Ledger-compatible m/44'/501' root for Solana.
        let min_segments = match self {
            Self::Solana => 2,
            Self::Ethereum | Self::Bitcoin => 3,
        };
        if path.len() < min_segments {
            return Err(WalletError::InvalidBip32Path(format!(
                "{operation} path must contain at least {min_segments} segments for {self:?}"
            )));
        }

        if let Some(inferred) = Self::from_bip32_path(path)
            && inferred != self
        {
            return Err(WalletError::InvalidBip32Path(format!(
                "chain/path mismatch: explicit {self:?} conflicts with inferred {inferred:?}"
            )));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedDerivationPath {
    pub chain: Chain,
    pub path: String,
    pub path_indices: Vec<u32>,
}

impl ResolvedDerivationPath {
    pub fn resolve(
        explicit_chain: Option<Chain>,
        explicit_path: Option<&str>,
    ) -> WalletResult<Self> {
        let parsed_path = explicit_path
            .map(|path| parse_bip32_path(path).map(|indices| (path.to_owned(), indices)))
            .transpose()?;

        let inferred_chain = parsed_path
            .as_ref()
            .and_then(|(_, indices)| Chain::from_bip32_path(indices));
        let chain = explicit_chain.or(inferred_chain).unwrap_or(Chain::Ethereum);

        if let (Some(explicit), Some(inferred), Some(path)) =
            (explicit_chain, inferred_chain, explicit_path)
            && explicit != inferred
        {
            return Err(WalletError::InvalidBip32Path(format!(
                "chain/path mismatch: explicit {explicit:?} conflicts with inferred {inferred:?} from path '{path}'"
            )));
        }

        let (path, path_indices) = match parsed_path {
            Some(parsed) => parsed,
            None => {
                let default_path = chain.default_path().to_owned();
                let path_indices = parse_bip32_path(&default_path)?;
                (default_path, path_indices)
            }
        };

        Ok(Self {
            chain,
            path,
            path_indices,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_chain_from_coin_type() {
        for (coin_type, expected) in [
            (0x8000_003c, Chain::Ethereum),
            (0x8000_0000, Chain::Bitcoin),
            (0x8000_01f5, Chain::Solana),
        ] {
            assert_eq!(
                Chain::from_bip32_path(&[0x8000_002c, coin_type]),
                Some(expected)
            );
        }
    }

    #[test]
    fn signing_path_minimum_length_is_chain_aware() {
        let solana_root = [44 | HARDENED, 501 | HARDENED];
        assert!(
            Chain::Solana
                .validate_signing_path(&solana_root, "sign")
                .is_ok()
        );
        assert!(
            Chain::Solana
                .validate_signing_path(&solana_root[..1], "sign")
                .is_err()
        );
        let eth_short = [44 | HARDENED, 60 | HARDENED];
        assert!(
            Chain::Ethereum
                .validate_signing_path(&eth_short, "sign")
                .is_err()
        );
    }

    #[test]
    fn resolve_defaults_to_eth_when_empty() {
        let resolved = ResolvedDerivationPath::resolve(None, None).expect("default resolution");
        assert_eq!(resolved.chain, Chain::Ethereum);
        assert_eq!(resolved.path, DEFAULT_ETHEREUM_BIP32_PATH);
    }

    #[test]
    fn resolve_uses_chain_default_path() {
        for chain in Chain::ALL {
            let resolved =
                ResolvedDerivationPath::resolve(Some(chain), None).expect("default path");
            assert_eq!(resolved.chain, chain);
            assert_eq!(resolved.path, chain.default_path());
        }
    }

    #[test]
    fn resolve_rejects_chain_path_mismatch() {
        let err = ResolvedDerivationPath::resolve(
            Some(Chain::Bitcoin),
            Some(DEFAULT_ETHEREUM_BIP32_PATH),
        )
        .expect_err("mismatch should fail");
        assert!(
            err.to_string().contains("chain/path mismatch"),
            "unexpected error: {err}"
        );
    }
}
