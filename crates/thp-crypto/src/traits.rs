use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid_key_material")]
    InvalidKeyMaterial,
    #[error("encryption_failure")]
    EncryptionFailure,
    #[error("decryption_failure")]
    DecryptionFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    pub k_tx: [u8; 32],
    pub k_rx: [u8; 32],
    pub session_id: [u8; 32],
}

impl Keys {
    pub fn zero() -> Self {
        Self {
            k_tx: [0u8; 32],
            k_rx: [0u8; 32],
            session_id: [0u8; 32],
        }
    }

    pub fn is_zero(&self) -> bool {
        self.k_tx.ct_eq(&[0u8; 32]).into()
            && self.k_rx.ct_eq(&[0u8; 32]).into()
            && self.session_id.ct_eq(&[0u8; 32]).into()
    }
}

pub trait CipherSuite {
    type EphemeralPriv;

    fn generate_keypair() -> (Self::EphemeralPriv, Vec<u8>);
    fn ecdh(privkey: &Self::EphemeralPriv, peer_pub: &[u8]) -> Result<[u8; 32], CryptoError>;
    fn kdf(shared: &[u8], salt: &[u8], info: &[u8]) -> Result<Keys, CryptoError>;
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}
