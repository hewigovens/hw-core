use hw_chain::Chain;
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
pub struct GetAddressRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
    pub show_display: bool,
    pub chunkify: bool,
    pub encoded_network: Option<Vec<u8>>,
    pub include_public_key: bool,
}

impl GetAddressRequest {
    pub fn ethereum(path: Vec<u32>) -> Self {
        Self {
            chain: Chain::Ethereum,
            path,
            show_display: false,
            chunkify: false,
            encoded_network: None,
            include_public_key: false,
        }
    }

    pub fn bitcoin(path: Vec<u32>) -> Self {
        Self {
            chain: Chain::Bitcoin,
            path,
            show_display: false,
            chunkify: false,
            encoded_network: None,
            include_public_key: false,
        }
    }

    pub fn solana(path: Vec<u32>) -> Self {
        Self {
            chain: Chain::Solana,
            path,
            show_display: false,
            chunkify: false,
            encoded_network: None,
            include_public_key: false,
        }
    }

    pub fn with_show_display(mut self, value: bool) -> Self {
        self.show_display = value;
        self
    }

    pub fn with_chunkify(mut self, value: bool) -> Self {
        self.chunkify = value;
        self
    }

    pub fn with_encoded_network(mut self, value: Option<Vec<u8>>) -> Self {
        self.encoded_network = value;
        self
    }

    pub fn with_include_public_key(mut self, value: bool) -> Self {
        self.include_public_key = value;
        self
    }
}

#[derive(Debug, Clone)]
pub struct GetAddressResponse {
    pub chain: Chain,
    pub address: String,
    pub mac: Option<Vec<u8>>,
    pub public_key: Option<String>,
}

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

#[derive(Debug, Clone)]
pub struct EthAccessListEntry {
    pub address: String,
    pub storage_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcInputScriptType {
    SpendAddress,
    SpendMultisig,
    External,
    SpendWitness,
    SpendP2shWitness,
    SpendTaproot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtcOutputScriptType {
    PayToAddress,
    PayToScriptHash,
    PayToMultisig,
    PayToOpReturn,
    PayToWitness,
    PayToP2shWitness,
    PayToTaproot,
}

#[derive(Debug, Clone)]
pub struct BtcSignInput {
    pub path: Vec<u32>,
    pub prev_hash: Vec<u8>,
    pub prev_index: u32,
    pub amount: u64,
    pub sequence: u32,
    pub script_type: BtcInputScriptType,
}

#[derive(Debug, Clone)]
pub struct BtcSignOutput {
    pub address: Option<String>,
    pub path: Vec<u32>,
    pub amount: u64,
    pub script_type: BtcOutputScriptType,
    pub op_return_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct BtcSignTx {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<BtcSignInput>,
    pub outputs: Vec<BtcSignOutput>,
    pub chunkify: bool,
}

#[derive(Debug, Clone)]
pub struct SignTxRequest {
    pub chain: Chain,
    pub path: Vec<u32>,
    pub nonce: Vec<u8>,
    pub max_fee_per_gas: Vec<u8>,
    pub max_priority_fee: Vec<u8>,
    pub gas_limit: Vec<u8>,
    pub to: String,
    pub value: Vec<u8>,
    pub data: Vec<u8>,
    pub chain_id: u64,
    pub access_list: Vec<EthAccessListEntry>,
    pub chunkify: bool,
    pub btc: Option<BtcSignTx>,
}

impl SignTxRequest {
    pub fn ethereum(path: Vec<u32>, chain_id: u64) -> Self {
        Self {
            chain: Chain::Ethereum,
            path,
            nonce: vec![0],
            max_fee_per_gas: vec![0],
            max_priority_fee: vec![0],
            gas_limit: vec![0],
            to: String::new(),
            value: vec![0],
            data: Vec::new(),
            chain_id,
            access_list: Vec::new(),
            chunkify: false,
            btc: None,
        }
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = nonce;
        self
    }

    pub fn with_max_fee_per_gas(mut self, max_fee_per_gas: Vec<u8>) -> Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    pub fn with_max_priority_fee(mut self, max_priority_fee: Vec<u8>) -> Self {
        self.max_priority_fee = max_priority_fee;
        self
    }

    pub fn with_gas_limit(mut self, gas_limit: Vec<u8>) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    pub fn with_to(mut self, to: String) -> Self {
        self.to = to;
        self
    }

    pub fn with_value(mut self, value: Vec<u8>) -> Self {
        self.value = value;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_access_list(mut self, access_list: Vec<EthAccessListEntry>) -> Self {
        self.access_list = access_list;
        self
    }

    pub fn with_chunkify(mut self, chunkify: bool) -> Self {
        self.chunkify = chunkify;
        self
    }

    pub fn bitcoin(tx: BtcSignTx) -> Self {
        Self {
            chain: Chain::Bitcoin,
            path: Vec::new(),
            nonce: vec![0],
            max_fee_per_gas: vec![0],
            max_priority_fee: vec![0],
            gas_limit: vec![0],
            to: String::new(),
            value: vec![0],
            data: Vec::new(),
            chain_id: 0,
            access_list: Vec::new(),
            chunkify: tx.chunkify,
            btc: Some(tx),
        }
    }

    pub fn solana(path: Vec<u32>, serialized_tx: Vec<u8>) -> Self {
        Self {
            chain: Chain::Solana,
            path,
            nonce: vec![0],
            max_fee_per_gas: vec![0],
            max_priority_fee: vec![0],
            gas_limit: vec![0],
            to: String::new(),
            value: vec![0],
            data: serialized_tx,
            chain_id: 0,
            access_list: Vec::new(),
            chunkify: false,
            btc: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignTxResponse {
    pub chain: Chain,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

#[async_trait::async_trait]
pub trait PairingController: Send + Sync {
    async fn on_prompt(
        &self,
        prompt: PairingPrompt,
    ) -> std::result::Result<PairingDecision, String>;
}
