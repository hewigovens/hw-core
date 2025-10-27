use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingMethod {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThpProperties {
    pub internal_model: String,
    pub model_variant: u32,
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
    pub pairing_methods: Vec<PairingMethod>,
}

#[derive(Debug, Clone)]
pub struct CreateChannelRequest {
    pub nonce: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct CreateChannelResponse {
    pub nonce: [u8; 8],
    pub channel: u16,
    pub handshake_hash: Vec<u8>,
    pub properties: ThpProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownCredential {
    pub credential: String,
    pub trezor_static_public_key: Option<Vec<u8>>,
    pub autoconnect: bool,
}

#[derive(Debug, Clone)]
pub struct HandshakeInitRequest {
    pub try_to_unlock: bool,
    pub handshake_hash: Vec<u8>,
    pub pairing_methods: Vec<PairingMethod>,
    pub static_key: Option<Vec<u8>>,
    pub known_credentials: Vec<KnownCredential>,
}

#[derive(Debug, Clone)]
pub struct HandshakeInitOutcome {
    pub host_encrypted_static_pubkey: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub trezor_encrypted_static_pubkey: Vec<u8>,
    pub handshake_hash: Vec<u8>,
    pub host_key: Vec<u8>,
    pub trezor_key: Vec<u8>,
    pub host_static_key: Vec<u8>,
    pub host_static_public_key: Vec<u8>,
    pub pairing_methods: Vec<PairingMethod>,
    pub credentials: Vec<KnownCredential>,
    pub selected_credential: Option<KnownCredential>,
    pub nfc_data: Option<Vec<u8>>,
    pub handshake_commitment: Option<Vec<u8>>,
    pub trezor_cpace_public_key: Option<Vec<u8>>,
    pub code_entry_challenge: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct HandshakeCompletionRequest {
    pub host_pubkey: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeCompletionState {
    RequiresPairing,
    Paired,
    AutoPaired,
}

#[derive(Debug, Clone)]
pub struct HandshakeCompletionResponse {
    pub state: HandshakeCompletionState,
}

#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub host_name: String,
    pub app_name: String,
}

#[derive(Debug, Clone)]
pub struct PairingRequestApproved;

#[derive(Debug, Clone)]
pub struct SelectMethodRequest {
    pub method: PairingMethod,
}

#[derive(Debug, Clone)]
pub enum SelectMethodResponse {
    End,
    CodeEntryCommitment { commitment: Vec<u8> },
    PairingPreparationsFinished { nfc_data: Option<Vec<u8>> },
}

#[derive(Debug, Clone)]
pub enum PairingTagRequest {
    QrCode {
        handshake_hash: Vec<u8>,
        tag: String,
    },
    Nfc {
        handshake_hash: Vec<u8>,
        tag: String,
    },
    CodeEntry {
        code: String,
        handshake_hash: Vec<u8>,
        commitment: Option<Vec<u8>>,
        challenge: Option<Vec<u8>>,
        trezor_cpace_public_key: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone)]
pub enum PairingTagResponse {
    Accepted { secret: Vec<u8> },
    Retry(String),
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

#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub passphrase: Option<String>,
    pub on_device: bool,
    pub derive_cardano: bool,
}

#[derive(Debug, Clone)]
pub struct CreateSessionResponse;

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

#[derive(Debug, Clone)]
pub struct PairingPrompt {
    pub available_methods: Vec<PairingMethod>,
    pub selected_method: PairingMethod,
    pub nfc_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum PairingDecision {
    SwitchMethod(PairingMethod),
    SubmitTag { method: PairingMethod, tag: String },
}

#[async_trait::async_trait]
pub trait PairingController: Send + Sync {
    async fn on_prompt(
        &self,
        prompt: PairingPrompt,
    ) -> std::result::Result<PairingDecision, String>;
}
