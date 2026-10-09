use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingMethod {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
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
pub struct CodeEntryChallengeRequest {
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CodeEntryChallengeResponse {
    pub trezor_cpace_public_key: Vec<u8>,
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
