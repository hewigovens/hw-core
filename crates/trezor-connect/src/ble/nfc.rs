use tracing::debug;

use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::crypto::validate_nfc_tag;
use crate::thp::types::PairingTagResponse;

const NFC_SECRET_LENGTH: usize = 16;
const NFC_HANDSHAKE_HASH_LENGTH: usize = 16;

/// Host secret shared with the device over NFC; the device proves knowledge of it in its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NfcSecret([u8; NFC_SECRET_LENGTH]);

impl NfcSecret {
    pub(super) fn random() -> Self {
        Self(rand::random())
    }

    /// Suite layout: the secret followed by the first 16 handshake hash bytes.
    pub(super) fn pairing_data(&self, handshake_hash: &[u8]) -> BackendResult<Vec<u8>> {
        let handshake_hash = handshake_hash
            .get(..NFC_HANDSHAKE_HASH_LENGTH)
            .ok_or_else(|| {
                BackendError::Transport(format!(
                    "NFC pairing requires at least {NFC_HANDSHAKE_HASH_LENGTH} handshake hash bytes"
                ))
            })?;
        Ok([self.0.as_slice(), handshake_hash].concat())
    }

    pub(super) fn validate_response(
        &self,
        handshake_hash: &[u8],
        response_tag: Vec<u8>,
    ) -> PairingTagResponse {
        if let Err(err) = validate_nfc_tag(handshake_hash, &response_tag, &self.0) {
            debug!("NFC tag validation failed: {err}");
            return PairingTagResponse::Retry("pairing tag mismatch".into());
        }
        PairingTagResponse::Accepted {
            secret: response_tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::thp::messages;

    #[test]
    fn nfc_pairing_data_and_response_match_suite_layout() {
        let handshake_hash = [0x21; 32];
        let secret = NfcSecret([0x34; NFC_SECRET_LENGTH]);
        let nfc_data = secret.pairing_data(&handshake_hash).unwrap();
        assert_eq!(&nfc_data[..NFC_SECRET_LENGTH], &secret.0);
        assert_eq!(
            &nfc_data[NFC_SECRET_LENGTH..],
            &handshake_hash[..NFC_HANDSHAKE_HASH_LENGTH]
        );

        let response_tag = Sha256::new()
            .chain_update([messages::ThpPairingMethod::Nfc as u8])
            .chain_update(handshake_hash)
            .chain_update(secret.0)
            .finalize()[..NFC_HANDSHAKE_HASH_LENGTH]
            .to_vec();
        assert!(matches!(
            secret.validate_response(&handshake_hash, response_tag),
            PairingTagResponse::Accepted { .. }
        ));
        assert!(matches!(
            secret.validate_response(&handshake_hash, vec![0; 16]),
            PairingTagResponse::Retry(_)
        ));
    }
}
