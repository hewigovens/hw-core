use trezor_connect::thp::types::{
    HostConfig as RawHostConfig, KnownCredential as RawKnownCredential,
    PairingMethod as RawPairingMethod,
};

pub type PairingMethod = RawPairingMethod;

#[uniffi::remote(Enum)]
pub enum PairingMethod {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
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

#[uniffi::export]
pub fn host_config_new(host_name: String, app_name: String) -> HostConfig {
    RawHostConfig::new(host_name, app_name).into()
}
