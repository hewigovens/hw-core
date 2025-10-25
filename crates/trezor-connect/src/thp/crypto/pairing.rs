use hex::FromHex;
use num_bigint::BigInt;
use rand_core::{CryptoRng, RngCore};
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

pub fn get_cpace_host_keys<R: RngCore + CryptoRng>(
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
    rng.fill_bytes(&mut private_key);
    let public_key = curve25519(&private_key, &generator);

    CpaceHostKeys {
        private_key,
        public_key,
    }
}

pub fn get_shared_secret(public_key: &[u8; 32], private_key: &[u8; 32]) -> [u8; 32] {
    let secret = diffie_hellman(private_key, public_key);
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
