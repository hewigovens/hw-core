pub mod curve25519;
pub mod pairing;
mod tools;

pub use curve25519::Curve25519KeyPair;
pub use pairing::{
    find_known_pairing_credentials, get_cpace_host_keys, get_handshake_hash, get_shared_secret,
    handle_handshake_init, validate_code_entry_tag, validate_nfc_tag, validate_qr_code_tag,
    HandshakeInitInput, HandshakeInitResult, PairingCryptoError,
};
pub use tools::{aes256gcm_decrypt, aes256gcm_encrypt, get_iv_from_nonce};
