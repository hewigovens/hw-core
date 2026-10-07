use hex::FromHex;
use num_bigint::BigInt;
use rand::{CryptoRng, Rng, RngExt};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use super::curve25519::{curve25519, elligator2};
use super::tools::{big_endian_bytes_to_bigint, hash_of_two, sha256};
use crate::thp::types::KnownCredential;

#[derive(Debug, Error)]
pub enum PairingCryptoError {
    #[error("hex decode error")]
    HexDecode,
    #[error("code mismatch")]
    CodeMismatch,
    #[error("commitment mismatch")]
    CommitmentMismatch,
}

impl From<hex::FromHexError> for PairingCryptoError {
    fn from(_: hex::FromHexError) -> Self {
        PairingCryptoError::HexDecode
    }
}

pub fn find_known_pairing_credentials(
    known_credentials: &[KnownCredential],
    trezor_masked_static_pubkey: &[u8; 32],
    trezor_ephemeral_pubkey: &[u8; 32],
) -> Vec<KnownCredential> {
    let mut matches = Vec::new();
    for cred in known_credentials {
        if let Some(static_key) = &cred.trezor_static_public_key {
            if static_key.len() != 32 {
                continue;
            }
            let mut static_arr = [0u8; 32];
            static_arr.copy_from_slice(static_key);
            let h = hash_of_two(static_key, trezor_ephemeral_pubkey);
            let derived = curve25519(&h, &static_arr);
            if derived == *trezor_masked_static_pubkey {
                matches.push(cred.clone());
            }
        }
    }
    matches
}

pub struct CpaceHostKeys {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

pub fn get_cpace_host_keys<R: Rng + CryptoRng>(
    code: &[u8],
    handshake_hash: &[u8],
    rng: &mut R,
) -> CpaceHostKeys {
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
    let mut sha_bytes = [0u8; 32];
    sha_bytes.copy_from_slice(&digest[..32]);

    let generator = elligator2(&sha_bytes);

    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key);
    let public_key = curve25519(&private_key, &generator);

    CpaceHostKeys {
        private_key,
        public_key,
    }
}

pub fn get_shared_secret(public_key: &[u8; 32], private_key: &[u8; 32]) -> [u8; 32] {
    let secret = curve25519(private_key, public_key);
    sha256(&secret)
}

pub fn validate_code_entry_tag(
    handshake_hash: &[u8],
    handshake_commitment: &[u8],
    code_entry_challenge: &[u8],
    value: &str,
    secret_hex: &str,
) -> Result<(), PairingCryptoError> {
    let secret_bytes = Vec::from_hex(secret_hex)?;
    let commitment = sha256(&secret_bytes);
    if commitment.as_slice() != handshake_commitment {
        return Err(PairingCryptoError::CommitmentMismatch);
    }

    let mut sha = Sha256::new();
    sha.update([2]);
    sha.update(handshake_hash);
    sha.update(&secret_bytes);
    sha.update(code_entry_challenge);
    let digest = sha.finalize();
    let calc = big_endian_bytes_to_bigint(&digest) % BigInt::from(1_000_000u32);
    let expected = value
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
    value_hex: &str,
    secret_hex: &str,
) -> Result<(), PairingCryptoError> {
    let secret = Vec::from_hex(secret_hex)?;
    let mut sha = Sha256::new();
    sha.update([3]);
    sha.update(handshake_hash);
    sha.update(&secret);
    let digest = sha.finalize();
    let expected = Vec::from_hex(value_hex)?;
    if expected.len() < 16 || digest[..16] != expected[..16] {
        return Err(PairingCryptoError::CodeMismatch);
    }
    Ok(())
}

pub fn validate_nfc_tag(
    handshake_hash: &[u8],
    value_hex: &str,
    secret: &[u8],
) -> Result<(), PairingCryptoError> {
    let mut sha = Sha256::new();
    sha.update([4]);
    sha.update(handshake_hash);
    sha.update(secret);
    let digest = sha.finalize();
    let expected = Vec::from_hex(value_hex)?;
    if expected.len() < 16 || digest[..16] != expected[..16] {
        return Err(PairingCryptoError::CodeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode as hex_encode;
    use num_traits::ToPrimitive;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::Sha512;

    #[test]
    fn cpace_keys_match_curve25519_generator() {
        let mut rng = StdRng::seed_from_u64(1337);
        let code = b"123456";
        let handshake_hash = [0xAA; 32];

        let keys = get_cpace_host_keys(code, &handshake_hash, &mut rng);

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
        let expected_public = curve25519(&keys.private_key, &generator);

        assert_eq!(keys.public_key, expected_public);
        assert_ne!(keys.public_key, [0u8; 32]);
    }

    #[test]
    fn validate_code_entry_tag_accepts_matching_inputs() {
        let handshake_hash = [0x10; 32];
        let secret = [0x22; 32];
        let handshake_commitment = sha256(&secret);
        let challenge = [0x33; 32];

        let mut sha = Sha256::new();
        sha.update([2]);
        sha.update(handshake_hash);
        sha.update(secret);
        sha.update(challenge);
        let digest = sha.finalize();
        let calc = (big_endian_bytes_to_bigint(&digest) % BigInt::from(1_000_000u32)).to_string();
        let value = format!("{calc:0>6}");
        let secret_hex = hex_encode(secret);

        validate_code_entry_tag(
            &handshake_hash,
            &handshake_commitment,
            &challenge,
            &value,
            &secret_hex,
        )
        .expect("validator succeeds");
    }

    #[test]
    fn validate_code_entry_tag_rejects_mismatch() {
        let handshake_hash = [0x44; 32];
        let secret = [0x55; 32];
        let handshake_commitment = sha256(&secret);
        let challenge = [0x66; 32];
        let secret_hex = hex_encode(secret);

        let mut sha = Sha256::new();
        sha.update([2]);
        sha.update(handshake_hash);
        sha.update(secret);
        sha.update(challenge);
        let digest = sha.finalize();
        let mut calc = (big_endian_bytes_to_bigint(&digest) % BigInt::from(1_000_000u32))
            .to_u32()
            .unwrap();
        calc = (calc + 1) % 1_000_000;
        let value = format!("{calc:0>6}");

        let err = validate_code_entry_tag(
            &handshake_hash,
            &handshake_commitment,
            &challenge,
            &value,
            &secret_hex,
        )
        .expect_err("validator should fail");
        assert!(matches!(err, PairingCryptoError::CodeMismatch));
    }

    #[test]
    fn validate_qr_code_tag_accepts_matching_inputs() {
        let handshake_hash = [0x12; 32];
        let secret = [0xAB; 32];
        let mut sha = Sha256::new();
        sha.update([3]);
        sha.update(handshake_hash);
        sha.update(secret);
        let digest = sha.finalize();

        let value_hex = hex_encode(&digest[..16]);
        let secret_hex = hex_encode(secret);

        validate_qr_code_tag(&handshake_hash, &value_hex, &secret_hex)
            .expect("QR validator succeeds");
    }

    #[test]
    fn validate_qr_code_tag_rejects_mismatch() {
        let handshake_hash = [0x12; 32];
        let secret = [0xAB; 32];
        let mut sha = Sha256::new();
        sha.update([3]);
        sha.update(handshake_hash);
        sha.update(secret);
        let digest = sha.finalize();

        let mut value_bytes = digest[..16].to_vec();
        value_bytes[0] ^= 0xFF;
        let value_hex = hex_encode(value_bytes);
        let secret_hex = hex_encode(secret);

        let err =
            validate_qr_code_tag(&handshake_hash, &value_hex, &secret_hex).expect_err("mismatch");
        assert!(matches!(err, PairingCryptoError::CodeMismatch));
    }

    #[test]
    fn validate_nfc_tag_accepts_matching_inputs() {
        let handshake_hash = [0x34; 32];
        let secret = [0x56; 16];
        let mut sha = Sha256::new();
        sha.update([4]);
        sha.update(handshake_hash);
        sha.update(secret);
        let digest = sha.finalize();
        let value_hex = hex_encode(&digest[..16]);

        validate_nfc_tag(&handshake_hash, &value_hex, &secret).expect("NFC validator succeeds");
    }

    #[test]
    fn validate_nfc_tag_rejects_mismatch() {
        let handshake_hash = [0x34; 32];
        let secret = [0x56; 16];
        let mut sha = Sha256::new();
        sha.update([4]);
        sha.update(handshake_hash);
        sha.update(secret);
        let digest = sha.finalize();
        let mut value = digest[..16].to_vec();
        value[5] ^= 0x01;
        let value_hex = hex_encode(value);

        let err =
            validate_nfc_tag(&handshake_hash, &value_hex, &secret).expect_err("validator fails");
        assert!(matches!(err, PairingCryptoError::CodeMismatch));
    }

    #[test]
    fn shared_secret_matches_curve25519_then_sha256() {
        let private_key = [0x11; 32];
        let public_key = [0x22; 32];
        let expected = sha256(&curve25519(&private_key, &public_key));
        let actual = get_shared_secret(&public_key, &private_key);
        assert_eq!(actual, expected);
    }
}
