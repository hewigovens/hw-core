use ble_transport::DeviceInfo;
use trezor_connect::thp::state::{HandshakeCache, ThpState};
use trezor_connect::thp::types::{HostConfig, KnownCredential, PairingMethod};
use trezor_connect::thp::Phase;

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

#[uniffi::export]
pub fn host_config_new(host_name: String, app_name: String) -> HWHostConfig {
    HostConfig::new(host_name, app_name)
}
