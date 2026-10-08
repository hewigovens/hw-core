use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};
use trezor_connect::thp::{EthSignTx, EthTxSignature};

use super::sighash::EthSignTxExt;
use crate::error::{WalletError, WalletResult};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedSignature {
    pub tx_hash: [u8; 32],
    pub recovered_address: String,
}

impl VerifiedSignature {
    /// Recovers the signer of `request` from the device's signature.
    pub fn recover(request: &EthSignTx, signature: &EthTxSignature) -> WalletResult<Self> {
        if signature.r.len() != 32 || signature.s.len() != 32 {
            return Err(WalletError::Signing(
                "invalid signature length (expected 32-byte r/s)".into(),
            ));
        }

        let tx_hash = request.eip1559_sighash()?;
        let recovery_id = recovery_id(signature.v)?;
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);
        let ecdsa_signature = Signature::from_slice(&sig_bytes)
            .map_err(|err| WalletError::Signing(format!("invalid signature bytes: {err}")))?;
        let verifying_key =
            VerifyingKey::recover_from_prehash(&tx_hash, &ecdsa_signature, recovery_id)
                .map_err(|err| WalletError::Signing(format!("failed to recover signer: {err}")))?;

        Ok(Self {
            tx_hash,
            recovered_address: checksum_address(&verifying_key)?,
        })
    }
}

fn recovery_id(v: u32) -> WalletResult<RecoveryId> {
    let parity = match v {
        0 | 1 => v as u8,
        27 | 28 => (v - 27) as u8,
        _ => {
            return Err(WalletError::Signing(format!(
                "unsupported signature `v` value: {v}"
            )));
        }
    };
    RecoveryId::try_from(parity)
        .map_err(|err| WalletError::Signing(format!("invalid recovery id: {err}")))
}

// EIP-55: uppercase each hex letter whose nibble in keccak(lowercase address) is >= 8.
fn checksum_address(verifying_key: &VerifyingKey) -> WalletResult<String> {
    let pubkey = verifying_key.to_sec1_point(false);
    let bytes = pubkey.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(WalletError::Signing(
            "unexpected public key format while deriving address".into(),
        ));
    }

    let lower = hex::encode(&Keccak256::digest(&bytes[1..])[12..]);
    let hash = Keccak256::digest(lower.as_bytes());
    let checksummed = lower
        .chars()
        .enumerate()
        .map(|(idx, ch)| {
            let nibble = (hash[idx / 2] >> (if idx % 2 == 0 { 4 } else { 0 })) & 0x0f;
            if ch.is_ascii_alphabetic() && nibble >= 8 {
                ch.to_ascii_uppercase()
            } else {
                ch
            }
        })
        .collect::<String>();
    Ok(format!("0x{checksummed}"))
}
