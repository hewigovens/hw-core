use hex::FromHex;
use num_bigint::BigInt;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use super::curve25519::{curve25519, diffie_hellman, elligator2};
use super::tools::{
    aes256gcm_decrypt, aes256gcm_encrypt, big_endian_bytes_to_bigint, get_iv_from_nonce,
    hash_of_two, hkdf, sha256,
};
use crate::thp::types::KnownCredential;

#[derive(Debug, Error)]
pub enum PairingCryptoError {
    #[error("invalid encrypted payload length")]
    InvalidEncryptedStaticKey,
    #[error("invalid credential static key")]
    InvalidStaticKey,
    #[error("aes failure")]
    Aes,
    #[error("hex decode error")]
    HexDecode,
    #[error("code mismatch")]
    CodeMismatch,
    #[error("commitment mismatch")]
    CommitmentMismatch,
}

impl From<aes_gcm::Error> for PairingCryptoError {
    fn from(_: aes_gcm::Error) -> Self {
        PairingCryptoError::Aes
    }
}

impl From<hex::FromHexError> for PairingCryptoError {
    fn from(_: hex::FromHexError) -> Self {
        PairingCryptoError::HexDecode
    }
}

fn protocol_name() -> Vec<u8> {
    let mut proto = b"Noise_XX_25519_AESGCM_SHA256".to_vec();
    proto.extend_from_slice(&[0u8; 4]);
    proto
}

pub fn get_handshake_hash(device_properties: &[u8]) -> [u8; 32] {
    hash_of_two(&protocol_name(), device_properties)
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

pub struct HandshakeInitResponse<'a> {
    pub trezor_ephemeral_pubkey: [u8; 32],
    pub trezor_encrypted_static_pubkey: &'a [u8],
    pub tag: [u8; 16],
}

pub struct HandshakeInitInput<'a, F>
where
    F: Fn(Option<&str>) -> Vec<u8> + Send + Sync + 'a,
{
    pub handshake_hash: [u8; 32],
    pub send_nonce: u64,
    pub recv_nonce: u64,
    pub host_static_private: [u8; 32],
    pub host_static_public: [u8; 32],
    pub host_ephemeral_private: [u8; 32],
    pub host_ephemeral_public: [u8; 32],
    pub try_to_unlock: bool,
    pub known_credentials: &'a [KnownCredential],
    pub response: HandshakeInitResponse<'a>,
    pub encode_handshake_payload: &'a F,
}

#[derive(Debug, Clone)]
pub struct HandshakeInitResult {
    pub trezor_masked_static_pubkey: [u8; 32],
    pub trezor_encrypted_static_pubkey: Vec<u8>,
    pub host_encrypted_static_pubkey: Vec<u8>,
    pub host_key: [u8; 32],
    pub trezor_key: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub credentials: Vec<KnownCredential>,
    pub selected_credential: Option<KnownCredential>,
    pub encrypted_payload: Vec<u8>,
}

pub fn handle_handshake_init<F>(
    input: HandshakeInitInput<F>,
) -> Result<HandshakeInitResult, PairingCryptoError>
where
    F: Fn(Option<&str>) -> Vec<u8> + Send + Sync,
{
    let HandshakeInitInput {
        mut handshake_hash,
        send_nonce,
        recv_nonce,
        host_static_private,
        host_static_public,
        host_ephemeral_private,
        host_ephemeral_public,
        try_to_unlock,
        known_credentials,
        response,
        encode_handshake_payload,
    } = input;

    if response.trezor_encrypted_static_pubkey.len() < 32 + 16 {
        return Err(PairingCryptoError::InvalidEncryptedStaticKey);
    }

    let iv0 = get_iv_from_nonce(send_nonce);
    let iv1 = get_iv_from_nonce(recv_nonce);

    handshake_hash = hash_of_two(&handshake_hash, &host_ephemeral_public);
    handshake_hash = hash_of_two(&handshake_hash, &[try_to_unlock as u8]);
    handshake_hash = hash_of_two(&handshake_hash, &response.trezor_ephemeral_pubkey);

    let point = diffie_hellman(&host_ephemeral_private, &response.trezor_ephemeral_pubkey);
    let (mut ck, mut k) = hkdf(&protocol_name(), &point);

    let (ciphertext, auth_tag_bytes) = response.trezor_encrypted_static_pubkey.split_at(32);
    let mut trezor_tag = [0u8; 16];
    trezor_tag.copy_from_slice(&auth_tag_bytes[..16]);
    let trezor_masked_static_pubkey =
        aes256gcm_decrypt(&k, &iv0, &handshake_hash, ciphertext, &trezor_tag)
            .map_err(|_| PairingCryptoError::Aes)?;
    let trezor_masked_static_pubkey: [u8; 32] =
        trezor_masked_static_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| PairingCryptoError::InvalidEncryptedStaticKey)?;

    handshake_hash = hash_of_two(&handshake_hash, response.trezor_encrypted_static_pubkey);

    let point = diffie_hellman(&host_ephemeral_private, &trezor_masked_static_pubkey);
    let (new_ck, new_k) = hkdf(&ck, &point);
    ck = new_ck;
    k = new_k;

    aes256gcm_decrypt(&k, &iv0, &handshake_hash, &[], &response.tag)
        .map_err(|_| PairingCryptoError::Aes)?;

    handshake_hash = hash_of_two(&handshake_hash, &response.tag);

    let credentials = find_known_pairing_credentials(
        known_credentials,
        &trezor_masked_static_pubkey,
        &response.trezor_ephemeral_pubkey,
    );
    let selected_credential = credentials.first().cloned();

    let (ciphertext, tag) = aes256gcm_encrypt(&k, &iv1, &handshake_hash, &host_static_public)
        .map_err(|_| PairingCryptoError::Aes)?;
    let mut host_encrypted_static_pubkey = ciphertext;
    host_encrypted_static_pubkey.extend_from_slice(&tag);

    handshake_hash = hash_of_two(&handshake_hash, &host_encrypted_static_pubkey);

    let point = diffie_hellman(&host_static_private, &response.trezor_ephemeral_pubkey);
    let (new_ck, new_k) = hkdf(&ck, &point);
    ck = new_ck;
    k = new_k;

    let payload =
        encode_handshake_payload(selected_credential.as_ref().map(|c| c.credential.as_str()));
    let (ciphertext, tag) = aes256gcm_encrypt(&k, &iv0, &handshake_hash, &payload)
        .map_err(|_| PairingCryptoError::Aes)?;
    let mut encrypted_payload = ciphertext;
    encrypted_payload.extend_from_slice(&tag);

    handshake_hash = hash_of_two(&handshake_hash, &encrypted_payload);

    let (host_key, trezor_key) = hkdf(&ck, &[]);

    Ok(HandshakeInitResult {
        trezor_masked_static_pubkey,
        trezor_encrypted_static_pubkey: response.trezor_encrypted_static_pubkey.to_vec(),
        host_encrypted_static_pubkey,
        host_key,
        trezor_key,
        handshake_hash,
        credentials,
        selected_credential,
        encrypted_payload,
    })
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
    // Match Trezor Suite implementation exactly: shared_secret = X25519(private, public),
    // then tag = SHA-256(shared_secret).
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
    use crate::thp::crypto::curve25519::get_curve25519_key_pair;
    use crate::thp::types::KnownCredential;
    use hex::encode as hex_encode;
    use num_traits::ToPrimitive;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::Sha512;

    fn encode_handshake_payload(credential: Option<&str>) -> Vec<u8> {
        match credential {
            Some(value) => format!("cred:{value}").into_bytes(),
            None => b"cred:<none>".to_vec(),
        }
    }

    #[test]
    fn handle_handshake_init_matches_expected() {
        let mut rng = StdRng::seed_from_u64(42);

        let host_static = get_curve25519_key_pair(&mut rng);
        let host_ephemeral = get_curve25519_key_pair(&mut rng);
        let trezor_static = get_curve25519_key_pair(&mut rng);
        let trezor_ephemeral = get_curve25519_key_pair(&mut rng);

        let device_properties = b"fixture-device-properties";
        let handshake_hash = get_handshake_hash(device_properties);
        let mut h = handshake_hash;

        let send_nonce = 0u64;
        let recv_nonce = 1u64;
        let iv0 = get_iv_from_nonce(send_nonce);
        let iv1 = get_iv_from_nonce(recv_nonce);
        let try_to_unlock = true;

        h = hash_of_two(&h, &host_ephemeral.public_key);
        h = hash_of_two(&h, &[try_to_unlock as u8]);
        h = hash_of_two(&h, &trezor_ephemeral.public_key);

        let mut ck_k = hkdf(
            &protocol_name(),
            &diffie_hellman(&host_ephemeral.private_key, &trezor_ephemeral.public_key),
        );
        let mut ck = ck_k.0;
        let mut k = ck_k.1;

        let mask_scalar = hash_of_two(&trezor_static.public_key, &trezor_ephemeral.public_key);
        let trezor_masked_static_pubkey = curve25519(&mask_scalar, &trezor_static.public_key);

        let (trezor_static_ciphertext, trezor_static_tag) =
            aes256gcm_encrypt(&k, &iv0, &h, &trezor_masked_static_pubkey).unwrap();
        let mut trezor_encrypted_static_pubkey = trezor_static_ciphertext.clone();
        trezor_encrypted_static_pubkey.extend_from_slice(&trezor_static_tag);

        h = hash_of_two(&h, &trezor_encrypted_static_pubkey);

        let diff_masked = diffie_hellman(&host_ephemeral.private_key, &trezor_masked_static_pubkey);
        ck_k = hkdf(&ck, &diff_masked);
        ck = ck_k.0;
        k = ck_k.1;

        let (_, empty_tag) = aes256gcm_encrypt(&k, &iv0, &h, &[]).unwrap();
        h = hash_of_two(&h, &empty_tag);

        let correct_credential = KnownCredential {
            credential: "cred-known".into(),
            trezor_static_public_key: Some(trezor_static.public_key.to_vec()),
            autoconnect: true,
        };
        let bogus_credential = KnownCredential {
            credential: "other".into(),
            trezor_static_public_key: Some(vec![0xAA; 32]),
            autoconnect: false,
        };
        let known_credentials = vec![correct_credential.clone(), bogus_credential];

        let expected_credentials = find_known_pairing_credentials(
            &known_credentials,
            &trezor_masked_static_pubkey,
            &trezor_ephemeral.public_key,
        );
        assert_eq!(expected_credentials.len(), 1);

        let (host_static_ciphertext, host_static_tag) =
            aes256gcm_encrypt(&k, &iv1, &h, &host_static.public_key).unwrap();
        let mut expected_host_encrypted_static_pubkey = host_static_ciphertext.clone();
        expected_host_encrypted_static_pubkey.extend_from_slice(&host_static_tag);

        h = hash_of_two(&h, &expected_host_encrypted_static_pubkey);

        let diff_static = diffie_hellman(&host_static.private_key, &trezor_ephemeral.public_key);
        ck_k = hkdf(&ck, &diff_static);
        ck = ck_k.0;
        k = ck_k.1;

        let payload_bytes = encode_handshake_payload(Some(&correct_credential.credential));
        let (payload_ciphertext, payload_tag) =
            aes256gcm_encrypt(&k, &iv0, &h, &payload_bytes).unwrap();
        let mut expected_encrypted_payload = payload_ciphertext.clone();
        expected_encrypted_payload.extend_from_slice(&payload_tag);

        h = hash_of_two(&h, &expected_encrypted_payload);

        let (expected_host_key, expected_trezor_key) = hkdf(&ck, &[]);

        let response = HandshakeInitResponse {
            trezor_ephemeral_pubkey: trezor_ephemeral.public_key,
            trezor_encrypted_static_pubkey: trezor_encrypted_static_pubkey.as_slice(),
            tag: empty_tag,
        };

        let result = handle_handshake_init(HandshakeInitInput {
            handshake_hash,
            send_nonce,
            recv_nonce,
            host_static_private: host_static.private_key,
            host_static_public: host_static.public_key,
            host_ephemeral_private: host_ephemeral.private_key,
            host_ephemeral_public: host_ephemeral.public_key,
            try_to_unlock,
            known_credentials: &known_credentials,
            response,
            encode_handshake_payload: &encode_handshake_payload,
        })
        .expect("handshake init succeeds");

        assert_eq!(
            result.trezor_encrypted_static_pubkey,
            trezor_encrypted_static_pubkey
        );
        assert_eq!(
            result.host_encrypted_static_pubkey,
            expected_host_encrypted_static_pubkey
        );
        assert_eq!(result.encrypted_payload, expected_encrypted_payload);
        assert_eq!(result.host_key, expected_host_key);
        assert_eq!(result.trezor_key, expected_trezor_key);
        assert_eq!(result.handshake_hash, h);
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(
            result
                .selected_credential
                .as_ref()
                .map(|c| c.credential.as_str()),
            Some(correct_credential.credential.as_str())
        );
        assert_eq!(
            result.credentials[0].trezor_static_public_key.as_deref(),
            Some(
                correct_credential
                    .trezor_static_public_key
                    .as_ref()
                    .unwrap()
                    .as_slice()
            )
        );
    }

    #[test]
    fn cpace_keys_match_curve25519_generator() {
        let mut rng = StdRng::seed_from_u64(1337);
        let code = b"123456";
        let handshake_hash = [0xAA; 32];

        let keys = get_cpace_host_keys(code, &handshake_hash, &mut rng);

        // Derive the generator deterministically per spec.
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
