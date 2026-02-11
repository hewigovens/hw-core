use ble_transport::DeviceInfo;
use trezor_connect::thp::Chain;
use trezor_connect::thp::Phase;
use trezor_connect::thp::state::{HandshakeCache, ThpState};
use trezor_connect::thp::types::{HostConfig, KnownCredential, PairingMethod};

pub type HWUuid = uuid::Uuid;

uniffi::custom_type!(HWUuid, String, {
    remote,
    lower: |uuid: HWUuid| uuid.to_string(),
    try_lift: |value: String| Ok(uuid::Uuid::parse_str(&value)?),
});

pub type HWPairingMethod = PairingMethod;

#[uniffi::remote(Enum)]
pub enum HWPairingMethod {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
}

pub type HWPhase = Phase;

#[uniffi::remote(Enum)]
pub enum HWPhase {
    Handshake,
    Pairing,
    Paired,
}

pub type HWChain = Chain;

#[uniffi::remote(Enum)]
pub enum HWChain {
    Ethereum,
    Bitcoin,
}

pub type HWKnownCredential = KnownCredential;

#[uniffi::remote(Record)]
pub struct HWKnownCredential {
    pub credential: String,
    pub trezor_static_public_key: Option<Vec<u8>>,
    pub autoconnect: bool,
}

pub type HWHostConfig = HostConfig;

#[uniffi::remote(Record)]
pub struct HWHostConfig {
    #[uniffi(default = [])]
    pub pairing_methods: Vec<HWPairingMethod>,
    pub known_credentials: Vec<HWKnownCredential>,
    pub static_key: Option<Vec<u8>>,
    pub host_name: String,
    pub app_name: String,
}

pub type HWBleDeviceInfo = DeviceInfo;

#[uniffi::remote(Record)]
pub struct HWBleDeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i32>,
    pub services: Vec<HWUuid>,
}

pub type HWHandshakeCache = HandshakeCache;

#[uniffi::remote(Record)]
pub struct HWHandshakeCache {
    pub channel: u16,
    pub handshake_hash: Vec<u8>,
    pub pairing_methods: Vec<HWPairingMethod>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWThpState {
    pub phase: HWPhase,
    pub is_paired: bool,
    pub autoconnect: bool,
    pub pairing_credentials: Vec<HWKnownCredential>,
    pub handshake_cache: Option<HWHandshakeCache>,
}

impl From<&ThpState> for HWThpState {
    fn from(state: &ThpState) -> Self {
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
pub enum HWWorkflowEventKind {
    Progress,
    PairingPrompt,
    ButtonRequest,
    Ready,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWWorkflowEvent {
    pub kind: HWWorkflowEventKind,
    pub code: String,
    pub message: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWPairingPrompt {
    pub available_methods: Vec<HWPairingMethod>,
    pub selected_method: Option<HWPairingMethod>,
    pub requires_connection_confirmation: bool,
    pub message: String,
}

#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum HWPairingProgressKind {
    AwaitingCode,
    AwaitingConnectionConfirmation,
    Completed,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWPairingProgress {
    pub kind: HWPairingProgressKind,
    pub message: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWGetAddressRequest {
    pub chain: HWChain,
    pub path: String,
    pub show_on_device: bool,
    pub include_public_key: bool,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWGetAddressResult {
    pub chain: HWChain,
    pub address: String,
    pub mac: Option<Vec<u8>>,
    pub public_key: Option<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWEthAccessListEntry {
    pub address: String,
    pub storage_keys: Vec<String>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWSignEthTxRequest {
    pub path: String,
    pub to: String,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub chain_id: u64,
    pub data: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee: String,
    pub access_list: Vec<HWEthAccessListEntry>,
    pub chunkify: bool,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct HWSignEthTxResult {
    pub v: u32,
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub tx_hash: Option<Vec<u8>>,
    pub recovered_address: Option<String>,
}

#[uniffi::export]
pub fn host_config_new(host_name: String, app_name: String) -> HWHostConfig {
    HostConfig::new(host_name, app_name)
}
