#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub passphrase: Option<String>,
    pub on_device: bool,
    pub derive_cardano: bool,
}

#[derive(Debug, Clone)]
pub struct CreateSessionResponse;
