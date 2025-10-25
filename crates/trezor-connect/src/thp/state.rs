use parking_lot::Mutex;

use super::types::{KnownCredential, PairingMethod};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Handshake,
    Pairing,
    Paired,
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCache {
    pub channel: u16,
    pub handshake_hash: Vec<u8>,
    pub pairing_methods: Vec<PairingMethod>,
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCredentials {
    pub pairing_methods: Vec<PairingMethod>,
    pub handshake_hash: Vec<u8>,
    pub trezor_encrypted_static_pubkey: Vec<u8>,
    pub host_encrypted_static_pubkey: Vec<u8>,
    pub host_key: Vec<u8>,
    pub trezor_key: Vec<u8>,
    pub host_static_key: Vec<u8>,
    pub host_static_public_key: Vec<u8>,
    pub nfc_data: Option<Vec<u8>>,
    pub handshake_commitment: Option<Vec<u8>>,
    pub trezor_cpace_public_key: Option<Vec<u8>>,
    pub code_entry_challenge: Option<Vec<u8>>,
    pub pairing_credentials: Vec<KnownCredential>,
    pub selected_credential: Option<KnownCredential>,
}

#[derive(Debug, Default)]
pub struct ThpState {
    inner: Mutex<StateInner>,
}

#[derive(Debug, Default)]
struct StateInner {
    phase: Phase,
    handshake_cache: Option<HandshakeCache>,
    handshake_credentials: Option<HandshakeCredentials>,
    pairing_method: Option<PairingMethod>,
    pairing_credentials: Vec<KnownCredential>,
    is_paired: bool,
    autoconnect_paired: bool,
}

impl ThpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> Phase {
        self.inner.lock().phase
    }

    pub fn set_phase(&self, phase: Phase) {
        self.inner.lock().phase = phase;
    }

    pub fn set_handshake_cache(&self, cache: HandshakeCache) {
        let mut inner = self.inner.lock();
        inner.handshake_cache = Some(cache);
        inner.phase = Phase::Handshake;
    }

    pub fn handshake_cache(&self) -> Option<HandshakeCache> {
        self.inner.lock().handshake_cache.clone()
    }

    pub fn set_handshake_credentials(&self, creds: HandshakeCredentials) {
        let mut inner = self.inner.lock();
        inner.handshake_credentials = Some(creds);
        inner.phase = Phase::Pairing;
    }

    pub fn handshake_credentials(&self) -> Option<HandshakeCredentials> {
        self.inner.lock().handshake_credentials.clone()
    }

    pub fn update_handshake_credentials<F>(&self, update: F)
    where
        F: FnOnce(&mut HandshakeCredentials),
    {
        let mut inner = self.inner.lock();
        if let Some(creds) = inner.handshake_credentials.as_mut() {
            update(creds);
        }
    }

    pub fn set_pairing_method(&self, method: PairingMethod) {
        self.inner.lock().pairing_method = Some(method);
    }

    pub fn pairing_method(&self) -> Option<PairingMethod> {
        self.inner.lock().pairing_method
    }

    pub fn set_pairing_credentials(&self, credentials: Vec<KnownCredential>) {
        let mut inner = self.inner.lock();
        inner.pairing_credentials = credentials.clone();
        if let Some(creds) = inner.handshake_credentials.as_mut() {
            creds.pairing_credentials = credentials;
        }
    }

    pub fn pairing_credentials(&self) -> Vec<KnownCredential> {
        self.inner.lock().pairing_credentials.clone()
    }

    pub fn set_is_paired(&self, paired: bool) {
        self.inner.lock().is_paired = paired;
    }

    pub fn is_paired(&self) -> bool {
        self.inner.lock().is_paired
    }

    pub fn set_autoconnect_paired(&self, value: bool) {
        self.inner.lock().autoconnect_paired = value;
    }

    pub fn is_autoconnect_paired(&self) -> bool {
        self.inner.lock().autoconnect_paired
    }

    pub fn reset(&self) {
        *self.inner.lock() = StateInner::default();
    }
}
