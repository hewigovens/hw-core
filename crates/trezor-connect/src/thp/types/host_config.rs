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
}
