use num_bigint::BigInt;
use rand::{CryptoRng, Rng, RngExt};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use super::curve25519::{curve25519, elligator2};
use super::tools::{big_endian_bytes_to_bigint, hash_of_two, sha256};
use crate::thp::types::KnownCredential;

#[derive(Debug, Error)]
pub enum PairingCryptoError {
    #[error("code mismatch")]
    CodeMismatch,
    #[error("commitment mismatch")]
    CommitmentMismatch,
}

impl KnownCredential {
    /// Whether this credential's device static key is the one the handshake masked with `ephemeral_pubkey`.
    pub fn matches_masked_key(
        &self,
        masked_static_pubkey: &[u8; 32],
        ephemeral_pubkey: &[u8; 32],
    ) -> bool {
        let Some(static_key) = self
            .trezor_static_public_key
            .as_deref()
            .and_then(|key| <&[u8; 32]>::try_from(key).ok())
        else {
            return false;
        };
        let mask = hash_of_two(static_key, ephemeral_pubkey);
        curve25519(&mask, static_key) == *masked_static_pubkey
    }
}

pub struct CpaceHostKeys {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

impl CpaceHostKeys {
    pub fn generate<R: Rng + CryptoRng>(code: &[u8], handshake_hash: &[u8], rng: &mut R) -> Self {
        let generator = elligator2(&cpace_pregenerator(code, handshake_hash));
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key);
        let public_key = curve25519(&private_key, &generator);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn shared_secret(&self, trezor_public_key: &[u8; 32]) -> [u8; 32] {
        sha256(&curve25519(&self.private_key, trezor_public_key))
    }
}

fn cpace_pregenerator(code: &[u8], handshake_hash: &[u8]) -> [u8; 32] {
    let mut sha = Sha512::new();
    sha.update([0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06]);
    sha.update(code);
    let mut padding = vec![0u8; 113];
    padding[0] = 0x6f;
    padding[112] = 0x20;
    sha.update(&padding);
    sha.update(handshake_hash);
    sha.update([0x00]);
    let digest = sha.finalize();
    let mut pregenerator = [0u8; 32];
    pregenerator.copy_from_slice(&digest[..32]);
    pregenerator
}

pub fn validate_code_entry_tag(
    handshake_hash: &[u8],
    handshake_commitment: &[u8],
    code_entry_challenge: &[u8],
    code: &str,
    secret: &[u8],
) -> Result<(), PairingCryptoError> {
    if sha256(secret).as_slice() != handshake_commitment {
        return Err(PairingCryptoError::CommitmentMismatch);
    }

    let mut sha = Sha256::new();
    sha.update([2]);
    sha.update(handshake_hash);
    sha.update(secret);
    sha.update(code_entry_challenge);
    let digest = sha.finalize();
    let calc = big_endian_bytes_to_bigint(&digest) % BigInt::from(1_000_000u32);
    let expected = code
        .parse::<u32>()
        .map(BigInt::from)
        .map_err(|_| PairingCryptoError::CodeMismatch)?;
    if calc != expected {
        return Err(PairingCryptoError::CodeMismatch);
    }
    Ok(())
}

pub fn validate_qr_code_tag(
    handshake_hash: &[u8],
    tag: &[u8],
    secret: &[u8],
) -> Result<(), PairingCryptoError> {
    validate_tag_prefix(3, handshake_hash, tag, secret)
}

pub fn validate_nfc_tag(
    handshake_hash: &[u8],
    tag: &[u8],
    secret: &[u8],
) -> Result<(), PairingCryptoError> {
    validate_tag_prefix(4, handshake_hash, tag, secret)
}

fn validate_tag_prefix(
    method: u8,
    handshake_hash: &[u8],
    tag: &[u8],
    secret: &[u8],
) -> Result<(), PairingCryptoError> {
    let mut sha = Sha256::new();
    sha.update([method]);
    sha.update(handshake_hash);
    sha.update(secret);
    let digest = sha.finalize();
    if tag.len() < 16 || digest[..16] != tag[..16] {
        return Err(PairingCryptoError::CodeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn cpace_keys_match_curve25519_generator() {
        let mut rng = StdRng::seed_from_u64(1337);
        let code = b"123456";
        let handshake_hash = [0xAA; 32];

        let keys = CpaceHostKeys::generate(code, &handshake_hash, &mut rng);

        let mut sha = Sha512::new();
        sha.update([0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06]);
        sha.update(code);
        let mut padding = vec![0u8; 113];
        padding[0] = 0x6f;
        padding[112] = 0x20;
        sha.update(&padding);
        sha.update(handshake_hash);
        sha.update([0x00]);
        let mut pregenerator = [0u8; 32];
        pregenerator.copy_from_slice(&sha.finalize()[..32]);

        let generator = elligator2(&pregenerator);
        assert_eq!(keys.public_key, curve25519(&keys.private_key, &generator));
        assert_ne!(keys.public_key, [0u8; 32]);

        let trezor_public_key = [0x22; 32];
        assert_eq!(
            keys.shared_secret(&trezor_public_key),
            sha256(&curve25519(&keys.private_key, &trezor_public_key))
        );
    }

    #[test]
    fn validate_code_entry_tag_checks_commitment_and_code() {
        let handshake_hash = [0x10; 32];
        let secret = [0x22; 32];
        let commitment = sha256(&secret);
        let challenge = [0x33; 32];

        let mut sha = Sha256::new();
        sha.update([2]);
        sha.update(handshake_hash);
        sha.update(secret);
        sha.update(challenge);
        let code = (big_endian_bytes_to_bigint(&sha.finalize()) % BigInt::from(1_000_000u32))
            .to_string()
            .parse::<u32>()
            .unwrap();
        let matching = format!("{code:0>6}");
        let wrong = format!("{:0>6}", (code + 1) % 1_000_000);

        let validate = |commitment: &[u8], code: &str| {
            validate_code_entry_tag(&handshake_hash, commitment, &challenge, code, &secret)
        };
        assert!(validate(&commitment, &matching).is_ok());
        assert!(matches!(
            validate(&commitment, &wrong),
            Err(PairingCryptoError::CodeMismatch)
        ));
        assert!(matches!(
            validate(&commitment, "abc"),
            Err(PairingCryptoError::CodeMismatch)
        ));
        assert!(matches!(
            validate(&[0; 32], &matching),
            Err(PairingCryptoError::CommitmentMismatch)
        ));
    }

    #[test]
    fn validate_qr_and_nfc_tags_compare_the_digest_prefix() {
        type Validator = fn(&[u8], &[u8], &[u8]) -> Result<(), PairingCryptoError>;
        let cases: [(u8, Validator); 2] = [(3, validate_qr_code_tag), (4, validate_nfc_tag)];
        let handshake_hash = [0x12; 32];
        let secret = [0xAB; 32];
        for (method, validate) in cases {
            let mut sha = Sha256::new();
            sha.update([method]);
            sha.update(handshake_hash);
            sha.update(secret);
            let tag = sha.finalize()[..16].to_vec();
            assert!(
                validate(&handshake_hash, &tag, &secret).is_ok(),
                "method {method}"
            );

            let mut flipped = tag.clone();
            flipped[5] ^= 0x01;
            for bad in [flipped, tag[..15].to_vec()] {
                assert!(
                    matches!(
                        validate(&handshake_hash, &bad, &secret),
                        Err(PairingCryptoError::CodeMismatch)
                    ),
                    "method {method}"
                );
            }
        }
    }

    #[test]
    fn known_credential_matches_only_its_masked_device_key() {
        let device_static = [0x31; 32];
        let device_public =
            crate::thp::crypto::Curve25519KeyPair::from_private_key(device_static).public_key;
        let ephemeral = [0x44; 32];
        let masked = curve25519(&hash_of_two(&device_public, &ephemeral), &device_public);
        let credential = |key: Option<Vec<u8>>| KnownCredential {
            credential: "aa".into(),
            trezor_static_public_key: key,
            autoconnect: false,
        };

        assert!(credential(Some(device_public.to_vec())).matches_masked_key(&masked, &ephemeral));
        assert!(!credential(Some(vec![0x99; 32])).matches_masked_key(&masked, &ephemeral));
        assert!(!credential(Some(vec![0x99; 31])).matches_masked_key(&masked, &ephemeral));
        assert!(!credential(None).matches_masked_key(&masked, &ephemeral));
    }
}
