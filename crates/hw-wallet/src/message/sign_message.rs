use std::collections::BTreeSet;

use hw_chain::Chain;
use trezor_connect::thp::types::SOLANA_PUBLIC_KEY_LEN;
use trezor_connect::thp::{SignMessageRequest, decode_solana_public_key};

use crate::chain::ChainPathExt;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

/// Firmware's OCMS v1 envelope stores the signer count in one byte.
pub(super) const MAX_SOLANA_MESSAGE_SIGNERS: usize = 255;

pub trait SignMessageRequestExt: Sized {
    /// `signers` are base58 public keys and apply to Solana only; empty means the signing key alone.
    fn from_message(
        chain: Chain,
        path: Vec<u32>,
        message: &str,
        is_hex: bool,
        chunkify: bool,
        signers: &[String],
    ) -> WalletResult<Self>;
}

impl SignMessageRequestExt for SignMessageRequest {
    fn from_message(
        chain: Chain,
        path: Vec<u32>,
        message: &str,
        is_hex: bool,
        chunkify: bool,
        signers: &[String],
    ) -> WalletResult<Self> {
        chain.validate_signing_path(&path, "message-sign")?;

        let message_bytes = if is_hex {
            decode(message)?
        } else {
            message.as_bytes().to_vec()
        };
        if message_bytes.is_empty() {
            return Err(WalletError::Signing(
                "message must not be empty after encoding".into(),
            ));
        }
        if chain != Chain::Solana && !signers.is_empty() {
            return Err(WalletError::Signing(format!(
                "message signers are only supported for Solana, not {chain:?}"
            )));
        }

        let request = match chain {
            Chain::Bitcoin => Self::bitcoin(path, message_bytes),
            Chain::Ethereum => Self::ethereum(path, message_bytes),
            Chain::Solana => {
                let message = String::from_utf8(message_bytes).map_err(|_| {
                    WalletError::Signing("Solana message must be valid UTF-8 text".into())
                })?;
                Self::solana(path, message, parse_solana_signers(signers)?)
            }
        };
        Ok(request.with_chunkify(chunkify))
    }
}

fn parse_solana_signers(signers: &[String]) -> WalletResult<Vec<[u8; SOLANA_PUBLIC_KEY_LEN]>> {
    if signers.len() > MAX_SOLANA_MESSAGE_SIGNERS {
        return Err(WalletError::Signing(format!(
            "Solana message supports at most {MAX_SOLANA_MESSAGE_SIGNERS} signers, got {}",
            signers.len()
        )));
    }
    let mut seen = BTreeSet::new();
    signers
        .iter()
        .map(|signer| {
            let signer = signer.trim();
            let key = decode_solana_public_key(signer).ok_or_else(|| {
                WalletError::Signing(format!(
                    "invalid Solana signer '{signer}': expected a base58 32-byte public key"
                ))
            })?;
            if !seen.insert(key) {
                return Err(WalletError::Signing(format!(
                    "duplicate Solana signer '{signer}'"
                )));
            }
            Ok(key)
        })
        .collect()
}
