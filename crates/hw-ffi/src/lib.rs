uniffi::setup_scaffolding!();

mod ble;
mod errors;
mod types;
mod version;

pub use crate::ble::{BleDiscoveredDevice, BleManagerHandle, BleSessionHandle, BleWorkflowHandle};
pub use crate::errors::HWCoreError;
pub use crate::types::{
    AccessListEntry, AddressResult, BleDeviceInfo, Chain, ChainConfig, GetAddressRequest,
    HandshakeCache, HostConfig, KnownCredential, PairingMethod, PairingProgress,
    PairingProgressKind, PairingPrompt, Phase, SessionHandshakeState, SessionPhase,
    SessionRetryPolicy, SessionState, SignTxRequest, SignTxResult, ThpState, Uuid, WorkflowEvent,
    WorkflowEventKind, chain_config, host_config_new, session_retry_policy_default,
};
pub use crate::version::hw_core_version;
