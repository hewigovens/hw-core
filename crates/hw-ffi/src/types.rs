use ble_transport::DeviceInfo as RawDeviceInfo;
use trezor_connect::thp::state::{HandshakeCache as RawHandshakeCache, ThpState as RawThpState};
use trezor_connect::thp::types::{
    HostConfig as RawHostConfig, KnownCredential as RawKnownCredential,
    PairingMethod as RawPairingMethod,
};
use trezor_connect::thp::{Chain as RawChain, Phase as RawPhase};

pub type Uuid = uuid::Uuid;

uniffi::custom_type!(Uuid, String, {
    remote,
    lower: |uuid: Uuid| uuid.to_string(),
    try_lift: |value: String| Ok(uuid::Uuid::parse_str(&value)?),
});

pub type PairingMethod = RawPairingMethod;

#[uniffi::remote(Enum)]
pub enum PairingMethod {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
}

pub type Phase = RawPhase;

#[uniffi::remote(Enum)]
pub enum Phase {
    Handshake,
    Pairing,
    Paired,
}

pub type Chain = RawChain;

#[uniffi::remote(Enum)]
pub enum Chain {
    Ethereum,
    Bitcoin,
}

pub type KnownCredential = RawKnownCredential;

#[uniffi::remote(Record)]
pub struct KnownCredential {
    pub credential: String,
    pub trezor_static_public_key: Option<Vec<u8>>,
    pub autoconnect: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HostConfig {
    #[uniffi(default = [])]
    pub pairing_methods: Vec<PairingMethod>,
    pub known_credentials: Vec<KnownCredential>,
    pub static_key: Option<Vec<u8>>,
    pub host_name: String,
    pub app_name: String,
}

impl From<HostConfig> for RawHostConfig {
    fn from(value: HostConfig) -> Self {
        Self {
            pairing_methods: value.pairing_methods,
            known_credentials: value.known_credentials,
            static_key: value.static_key,
            host_name: value.host_name,
            app_name: value.app_name,
        }
    }
}

impl From<RawHostConfig> for HostConfig {
    fn from(value: RawHostConfig) -> Self {
        Self {
            pairing_methods: value.pairing_methods,
            known_credentials: value.known_credentials,
            static_key: value.static_key,
            host_name: value.host_name,
            app_name: value.app_name,
        }
    }
}

pub type BleDeviceInfo = RawDeviceInfo;

#[uniffi::remote(Record)]
pub struct BleDeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub services: Vec<Uuid>,
}

pub type HandshakeCache = RawHandshakeCache;

#[uniffi::remote(Record)]
pub struct HandshakeCache {
    pub channel: u16,
    pub handshake_hash: Vec<u8>,
    pub pairing_methods: Vec<PairingMethod>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct ThpState {
    pub phase: Phase,
    pub is_paired: bool,
    pub autoconnect: bool,
    pub pairing_credentials: Vec<KnownCredential>,
    pub handshake_cache: Option<HandshakeCache>,
}

impl From<&RawThpState> for ThpState {
    fn from(state: &RawThpState) -> Self {
        Self {
            phase: state.phase(),
            is_paired: state.is_paired(),
            autoconnect: state.is_autoconnect_paired(),
            pairing_credentials: state.pairing_credentials().to_vec(),
            handshake_cache: state.handshake_cache().cloned(),
        }
    }
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum WorkflowEventKind {
    Progress,
    PairingPrompt,
    ButtonRequest,
    Ready,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct WorkflowEvent {
    pub kind: WorkflowEventKind,
    pub code: String,
    pub message: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingPrompt {
    pub available_methods: Vec<PairingMethod>,
    pub selected_method: Option<PairingMethod>,
    pub requires_connection_confirmation: bool,
    pub message: String,
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum SessionHandshakeState {
    Ready,
    PairingRequired { prompt: PairingPrompt },
    ConnectionConfirmationRequired { prompt: PairingPrompt },
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum PairingProgressKind {
    AwaitingCode,
    AwaitingConnectionConfirmation,
    Completed,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingProgress {
    pub kind: PairingProgressKind,
    pub message: String,
}

pub type SessionPhase = hw_wallet::ble::SessionPhase;

#[uniffi::remote(Enum)]
pub enum SessionPhase {
    NeedsChannel,
    NeedsHandshake,
    NeedsPairingCode,
    NeedsConnectionConfirmation,
    NeedsSession,
    Ready,
}

pub type SessionState = hw_wallet::ble::SessionState;

#[uniffi::remote(Record)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub can_pair_only: bool,
    pub can_connect: bool,
    pub can_get_address: bool,
    pub can_sign_tx: bool,
    pub requires_pairing_code: bool,
    pub prompt_message: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct GetAddressRequest {
    pub chain: Chain,
    pub path: String,
    pub show_on_device: bool,
    pub include_public_key: bool,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AddressResult {
    pub chain: Chain,
    pub address: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AccessListEntry {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTxRequest {
    pub chain: Chain,
    pub path: String,
    pub to: String,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub chain_id: u64,
    pub data: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee: String,
    pub access_list: Vec<AccessListEntry>,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct SignTxResult {
    pub chain: Chain,
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub tx_hash: Option<Vec<u8>>,
    pub recovered_address: Option<String>,
}

#[uniffi::export]
pub fn host_config_new(host_name: String, app_name: String) -> HostConfig {
    RawHostConfig::new(host_name, app_name).into()
}
