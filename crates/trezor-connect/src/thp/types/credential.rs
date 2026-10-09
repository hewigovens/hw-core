use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownCredential {
    pub credential: String,
    pub trezor_static_public_key: Option<Vec<u8>>,
    pub autoconnect: bool,
}

#[derive(Debug, Clone)]
pub struct CredentialRequest {
    pub autoconnect: bool,
    pub host_static_public_key: Vec<u8>,
    pub credential: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialResponse {
    pub trezor_static_public_key: Vec<u8>,
    pub credential: String,
    pub autoconnect: bool,
}
