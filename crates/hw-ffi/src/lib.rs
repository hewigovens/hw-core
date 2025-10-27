uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DeviceInfo, DiscoveredDevice};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::state::{HandshakeCache, ThpState};
use trezor_connect::thp::types::{HostConfig, KnownCredential, PairingMethod};
use trezor_connect::thp::Phase;
use trezor_connect::thp::{BackendError, ThpWorkflow, ThpWorkflowError};
use uuid::Uuid;

/// Public error type surfaced to foreign-language bindings.
#[derive(Debug, Error, uniffi::Error)]
pub enum FfiError {
    #[error("BLE profile not built into this binary")]
    UnsupportedProfile,
    #[error("BLE error: {0}")]
    Ble(String),
    #[error("Backend error: {0}")]
    Backend(String),
    #[error("Workflow error: {0}")]
    Workflow(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<ble_transport::BleError> for FfiError {
    fn from(err: ble_transport::BleError) -> Self {
        Self::Ble(err.to_string())
    }
}

impl From<BackendError> for FfiError {
    fn from(err: BackendError) -> Self {
        Self::Backend(err.to_string())
    }
}

impl From<ThpWorkflowError> for FfiError {
    fn from(err: ThpWorkflowError) -> Self {
        Self::Workflow(err.to_string())
    }
}

#[derive(uniffi::Enum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum PairingMethodFfi {
    QrCode,
    Nfc,
    CodeEntry,
    SkipPairing,
}

impl From<PairingMethod> for PairingMethodFfi {
    fn from(value: PairingMethod) -> Self {
        match value {
            PairingMethod::QrCode => Self::QrCode,
            PairingMethod::Nfc => Self::Nfc,
            PairingMethod::CodeEntry => Self::CodeEntry,
            PairingMethod::SkipPairing => Self::SkipPairing,
        }
    }
}

impl From<PairingMethodFfi> for PairingMethod {
    fn from(value: PairingMethodFfi) -> Self {
        match value {
            PairingMethodFfi::QrCode => Self::QrCode,
            PairingMethodFfi::Nfc => Self::Nfc,
            PairingMethodFfi::CodeEntry => Self::CodeEntry,
            PairingMethodFfi::SkipPairing => Self::SkipPairing,
        }
    }
}

#[derive(uniffi::Enum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum PhaseFfi {
    Handshake,
    Pairing,
    Paired,
}

impl From<Phase> for PhaseFfi {
    fn from(value: Phase) -> Self {
        match value {
            Phase::Handshake => Self::Handshake,
            Phase::Pairing => Self::Pairing,
            Phase::Paired => Self::Paired,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct KnownCredentialRecord {
    pub credential: String,
    pub trezor_static_public_key: Option<Vec<u8>>,
    pub autoconnect: bool,
}

impl From<KnownCredential> for KnownCredentialRecord {
    fn from(value: KnownCredential) -> Self {
        Self {
            credential: value.credential,
            trezor_static_public_key: value.trezor_static_public_key,
            autoconnect: value.autoconnect,
        }
    }
}

impl From<KnownCredentialRecord> for KnownCredential {
    fn from(value: KnownCredentialRecord) -> Self {
        Self {
            credential: value.credential,
            trezor_static_public_key: value.trezor_static_public_key,
            autoconnect: value.autoconnect,
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct HostConfigRecord {
    pub host_name: String,
    pub app_name: String,
    #[uniffi(default = [])]
    pub pairing_methods: Vec<PairingMethodFfi>,
    pub known_credentials: Vec<KnownCredentialRecord>,
    pub static_key: Option<Vec<u8>>,
}

impl From<HostConfigRecord> for HostConfig {
    fn from(value: HostConfigRecord) -> Self {
        let mut config = HostConfig::new(value.host_name, value.app_name);
        config.pairing_methods = value
            .pairing_methods
            .into_iter()
            .map(PairingMethod::from)
            .collect();
        config.known_credentials = value
            .known_credentials
            .into_iter()
            .map(KnownCredential::from)
            .collect();
        config.static_key = value.static_key;
        config
    }
}

impl From<&HostConfig> for HostConfigRecord {
    fn from(value: &HostConfig) -> Self {
        Self {
            host_name: value.host_name.clone(),
            app_name: value.app_name.clone(),
            pairing_methods: value
                .pairing_methods
                .iter()
                .copied()
                .map(PairingMethodFfi::from)
                .collect(),
            known_credentials: value
                .known_credentials
                .iter()
                .cloned()
                .map(KnownCredentialRecord::from)
                .collect(),
            static_key: value.static_key.clone(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct BleDeviceInfoRecord {
    pub id: String,
    pub name: Option<String>,
    pub rssi: Option<i16>,
    pub services: Vec<String>,
}

impl From<&DeviceInfo> for BleDeviceInfoRecord {
    fn from(value: &DeviceInfo) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            rssi: value.rssi,
            services: value.services.iter().map(Uuid::to_string).collect(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct HandshakeCacheRecord {
    pub channel: u16,
    pub handshake_hash: Vec<u8>,
    pub pairing_methods: Vec<PairingMethodFfi>,
}

impl From<HandshakeCache> for HandshakeCacheRecord {
    fn from(value: HandshakeCache) -> Self {
        Self {
            channel: value.channel,
            handshake_hash: value.handshake_hash,
            pairing_methods: value
                .pairing_methods
                .into_iter()
                .map(PairingMethodFfi::from)
                .collect(),
        }
    }
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ThpStateRecord {
    pub phase: PhaseFfi,
    pub is_paired: bool,
    pub autoconnect: bool,
    pub pairing_credentials: Vec<KnownCredentialRecord>,
    pub handshake_cache: Option<HandshakeCacheRecord>,
}

impl From<&ThpState> for ThpStateRecord {
    fn from(state: &ThpState) -> Self {
        Self {
            phase: state.phase().into(),
            is_paired: state.is_paired(),
            autoconnect: state.is_autoconnect_paired(),
            pairing_credentials: state
                .pairing_credentials()
                .into_iter()
                .map(KnownCredentialRecord::from)
                .collect(),
            handshake_cache: state.handshake_cache().map(HandshakeCacheRecord::from),
        }
    }
}

#[derive(uniffi::Object)]
pub struct BleManagerHandle {
    manager: BleManager,
}

#[uniffi::export]
impl BleManagerHandle {
    #[uniffi::constructor]
    pub async fn new() -> Result<Self, FfiError> {
        let manager = BleManager::new().await.map_err(FfiError::from)?;
        Ok(Self { manager })
    }

    #[uniffi::method]
    pub async fn discover_trezor(
        &self,
        duration_ms: u64,
    ) -> Result<Vec<Arc<BleDiscoveredDevice>>, FfiError> {
        let profile = BleProfile::trezor_safe7().ok_or(FfiError::UnsupportedProfile)?;
        let devices = self
            .manager
            .scan_profile(profile, Duration::from_millis(duration_ms))
            .await
            .map_err(FfiError::from)?;
        Ok(devices
            .into_iter()
            .map(|device| Arc::new(BleDiscoveredDevice::new(device, profile)))
            .collect())
    }
}

#[derive(uniffi::Object)]
pub struct BleDiscoveredDevice {
    device: Mutex<Option<DiscoveredDevice>>,
    info: DeviceInfo,
    profile: BleProfile,
}

impl BleDiscoveredDevice {
    fn new(device: DiscoveredDevice, profile: BleProfile) -> Self {
        let info = device.info().clone();
        Self {
            device: Mutex::new(Some(device)),
            info,
            profile,
        }
    }
}

#[uniffi::export]
impl BleDiscoveredDevice {
    pub fn info(&self) -> BleDeviceInfoRecord {
        BleDeviceInfoRecord::from(&self.info)
    }

    #[uniffi::method]
    pub async fn connect(&self) -> Result<Arc<BleSessionHandle>, FfiError> {
        let (info, peripheral) = {
            let mut slot = self.device.lock().expect("poisoned mutex");
            let device = slot
                .take()
                .ok_or_else(|| FfiError::InvalidState("device already connected".into()))?;
            device.into_parts()
        };

        let session = BleSession::new(peripheral, self.profile, info.clone())
            .await
            .map_err(FfiError::from)?;

        Ok(Arc::new(BleSessionHandle::new(session, info)))
    }
}

#[derive(uniffi::Object)]
pub struct BleSessionHandle {
    session: AsyncMutex<Option<BleSession>>,
    info: DeviceInfo,
}

impl BleSessionHandle {
    fn new(session: BleSession, info: DeviceInfo) -> Self {
        Self {
            session: AsyncMutex::new(Some(session)),
            info,
        }
    }

    async fn take_session(&self) -> Result<BleSession, FfiError> {
        let mut guard = self.session.lock().await;
        guard
            .take()
            .ok_or_else(|| FfiError::InvalidState("BLE session already consumed".into()))
    }
}

#[uniffi::export]
impl BleSessionHandle {
    #[uniffi::method]
    pub fn device_info(&self) -> BleDeviceInfoRecord {
        BleDeviceInfoRecord::from(&self.info)
    }

    #[uniffi::method]
    pub async fn into_workflow(
        self: Arc<Self>,
        config: HostConfigRecord,
    ) -> Result<Arc<BleWorkflowHandle>, FfiError> {
        let session = self.take_session().await?;
        let backend = BleBackend::from_session(session);
        let workflow = ThpWorkflow::new(backend, config.into());
        Ok(Arc::new(BleWorkflowHandle::new(workflow)))
    }
}

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
}

impl BleWorkflowHandle {
    fn new(workflow: ThpWorkflow<BleBackend>) -> Self {
        Self {
            workflow: AsyncMutex::new(workflow),
        }
    }
}

#[uniffi::export]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn create_channel(&self) -> Result<HandshakeCacheRecord, FfiError> {
        let mut workflow = self.workflow.lock().await;
        workflow.create_channel().await?;
        let cache = workflow
            .state()
            .handshake_cache()
            .ok_or_else(|| FfiError::InvalidState("handshake cache missing".into()))?;
        Ok(cache.into())
    }

    #[uniffi::method]
    pub async fn handshake(&self, try_to_unlock: bool) -> Result<(), FfiError> {
        let mut workflow = self.workflow.lock().await;
        workflow.handshake(try_to_unlock).await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), FfiError> {
        let mut workflow = self.workflow.lock().await;
        workflow
            .create_session(passphrase, on_device, derive_cardano)
            .await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn abort(&self) -> Result<(), FfiError> {
        let mut workflow = self.workflow.lock().await;
        workflow.abort().await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn state(&self) -> ThpStateRecord {
        let workflow = self.workflow.lock().await;
        ThpStateRecord::from(workflow.state())
    }

    #[uniffi::method]
    pub async fn host_config(&self) -> HostConfigRecord {
        let workflow = self.workflow.lock().await;
        HostConfigRecord::from(workflow.host_config())
    }
}

#[uniffi::export]
pub fn hw_core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[uniffi::export]
pub fn host_config_new(host_name: String, app_name: String) -> HostConfigRecord {
    HostConfigRecord {
        host_name,
        app_name,
        pairing_methods: Vec::new(),
        known_credentials: Vec::new(),
        static_key: None,
    }
}
