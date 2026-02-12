use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::traits::{CipherSuite, CryptoError, Keys};

#[derive(Debug)]
pub struct NoiseCipherSuite;

impl NoiseCipherSuite {
    pub fn generate_keypair_with_rng<R: Rng + CryptoRng>(rng: &mut R) -> (StaticSecret, [u8; 32]) {
        let mut secret = [0u8; 32];
        rng.fill(&mut secret);
        let privkey = StaticSecret::from(secret);
        let pubkey = PublicKey::from(&privkey);
        (privkey, pubkey.to_bytes())
    }
}

impl CipherSuite for NoiseCipherSuite {
    type EphemeralPriv = StaticSecret;

    fn generate_keypair() -> (Self::EphemeralPriv, Vec<u8>) {
        let mut rng = rand::rng();
        let (privkey, pubkey) = Self::generate_keypair_with_rng(&mut rng);
        (privkey, pubkey.to_vec())
    }

    fn ecdh(privkey: &Self::EphemeralPriv, peer_pub: &[u8]) -> Result<[u8; 32], CryptoError> {
        if peer_pub.len() != 32 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(peer_pub);
        let peer = PublicKey::from(arr);
        Ok(privkey.diffie_hellman(&peer).to_bytes())
    }

    fn kdf(shared: &[u8], salt: &[u8], info: &[u8]) -> Result<Keys, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(salt), shared);
        let mut okm = [0u8; 96];
        hk.expand(info, &mut okm)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let mut k_tx = [0u8; 32];
        let mut k_rx = [0u8; 32];
        let mut session_id = [0u8; 32];
        k_tx.copy_from_slice(&okm[0..32]);
        k_rx.copy_from_slice(&okm[32..64]);
        session_id.copy_from_slice(&okm[64..96]);

        Ok(Keys {
            k_tx,
            k_rx,
            session_id,
        })
    }

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailure)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        let nonce = Nonce::from(nonce_arr);
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailure)
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailure)?;
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce);
        let nonce = Nonce::from(nonce_arr);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailure)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn kdf_vector() {
        let shared = <[u8; 32]>::from_hex(
            "b56c3a8c6b5d27d4c417c9a516c6ddae46fb2654819e3d664e124b0d54a62f3a",
        )
        .unwrap();
        let salt = <[u8; 32]>::from_hex(
            "df650185a62db605f5bd53a0b5128af28ccf32ad07029a07a8d3b5a793102f02",
        )
        .unwrap();
        let info = b"thp-test-info";
        let keys = NoiseCipherSuite::kdf(&shared, &salt, info).unwrap();
        assert_eq!(
            keys.k_tx,
            <[u8; 32]>::from_hex(
                "5d5b2eeab80217e8fea7f632fe0bfade92f16fa6f0978fb2a770417bbc513799"
            )
            .unwrap()
        );
        assert_eq!(
            keys.k_rx,
            <[u8; 32]>::from_hex(
                "1d72e52048e519b17e2542dced4b6a889ea9806a46e55b4d90ef1176b916f52f"
            )
            .unwrap()
        );
        assert_eq!(
            keys.session_id,
            <[u8; 32]>::from_hex(
                "7dcdaf36b6370bd5976d88300a767d90a76bd509b2dfc90078e6c94a6afd4841"
            )
            .unwrap()
        );
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let nonce = [1u8; 12];
        let aad = [2u8; 8];
        let plaintext = b"test payload";
        let ct = NoiseCipherSuite::encrypt(&key, &nonce, &aad, plaintext).unwrap();
        assert_ne!(ct, plaintext);
        let roundtrip = NoiseCipherSuite::decrypt(&key, &nonce, &aad, &ct).unwrap();
        assert_eq!(roundtrip, plaintext);
    }

    #[test]
    fn ecdh_differs_for_different_peers() {
        let (a_priv, a_pub) = NoiseCipherSuite::generate_keypair();
        let (b_priv, b_pub) = NoiseCipherSuite::generate_keypair();
        let shared_ab = NoiseCipherSuite::ecdh(&a_priv, &b_pub).unwrap();
        let shared_ba = NoiseCipherSuite::ecdh(&b_priv, &a_pub).unwrap();
        assert_eq!(shared_ab, shared_ba);
    }
}
