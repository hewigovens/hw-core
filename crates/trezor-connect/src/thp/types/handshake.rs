use super::KnownCredential;

#[derive(Debug, Clone)]
pub struct HandshakeRequest {
    pub static_key: [u8; 32],
    pub known_credentials: Vec<KnownCredential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeCompletionState {
    RequiresPairing,
    Paired,
    AutoPaired,
}

#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub state: HandshakeCompletionState,
    pub handshake_hash: Vec<u8>,
    pub selected_credential: Option<KnownCredential>,
}
