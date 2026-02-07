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
        self.phase
    }

    pub fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }

    pub fn set_handshake_cache(&mut self, cache: HandshakeCache) {
        self.handshake_cache = Some(cache);
        self.phase = Phase::Handshake;
    }

    pub fn handshake_cache(&self) -> Option<&HandshakeCache> {
        self.handshake_cache.as_ref()
    }

    pub fn set_handshake_credentials(&mut self, creds: HandshakeCredentials) {
        self.handshake_credentials = Some(creds);
        self.phase = Phase::Pairing;
    }

    pub fn handshake_credentials(&self) -> Option<&HandshakeCredentials> {
        self.handshake_credentials.as_ref()
    }

    pub fn update_handshake_credentials<F>(&mut self, update: F)
    where
        F: FnOnce(&mut HandshakeCredentials),
    {
        if let Some(creds) = self.handshake_credentials.as_mut() {
            update(creds);
        }
    }

    pub fn set_pairing_method(&mut self, method: PairingMethod) {
        self.pairing_method = Some(method);
    }

    pub fn pairing_method(&self) -> Option<PairingMethod> {
        self.pairing_method
    }

    pub fn set_pairing_credentials(&mut self, credentials: Vec<KnownCredential>) {
        if let Some(creds) = self.handshake_credentials.as_mut() {
            creds.pairing_credentials = credentials.clone();
        }
        self.pairing_credentials = credentials;
    }

    pub fn pairing_credentials(&self) -> &[KnownCredential] {
        &self.pairing_credentials
    }

    pub fn set_is_paired(&mut self, paired: bool) {
        self.is_paired = paired;
    }

    pub fn is_paired(&self) -> bool {
        self.is_paired
    }

    pub fn set_autoconnect_paired(&mut self, value: bool) {
        self.autoconnect_paired = value;
    }

    pub fn is_autoconnect_paired(&self) -> bool {
        self.autoconnect_paired
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}
