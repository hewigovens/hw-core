use rand::{Rng, RngExt};

use super::{KnownCredential, PairingMethod};

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub pairing_methods: Vec<PairingMethod>,
    pub known_credentials: Vec<KnownCredential>,
    pub static_key: Option<Vec<u8>>,
    pub host_name: String,
    pub app_name: String,
}

impl HostConfig {
    pub fn new(host_name: impl Into<String>, app_name: impl Into<String>) -> Self {
        Self {
            pairing_methods: Vec::new(),
            known_credentials: Vec::new(),
            static_key: None,
            host_name: host_name.into(),
            app_name: app_name.into(),
        }
    }

    /// Returns the persistent host static key, generating and keeping one on first use.
    pub fn static_key_or_generate(&mut self, rng: &mut impl Rng) -> [u8; 32] {
        if let Some(key) = self
            .static_key
            .as_deref()
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
        {
            return key;
        }
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        self.static_key = Some(key.to_vec());
        key
    }

    /// Stores `credential`, replacing any earlier entry with the same credential.
    pub fn remember_credential(&mut self, credential: KnownCredential) {
        self.forget_credential(&credential.credential);
        self.known_credentials.push(credential);
    }

    pub fn forget_credential(&mut self, credential: &str) {
        self.known_credentials
            .retain(|c| c.credential != credential);
    }
}
