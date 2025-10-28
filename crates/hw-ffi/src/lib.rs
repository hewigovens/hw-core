uniffi::setup_scaffolding!();

mod ble;
mod errors;
mod types;
mod version;

pub use crate::ble::{BleDiscoveredDevice, BleManagerHandle, BleSessionHandle, BleWorkflowHandle};
pub use crate::errors::HWCoreError;
pub use crate::types::{
    host_config_new, HWBleDeviceInfo, HWHandshakeCache, HWHostConfig, HWKnownCredential,
    HWPairingMethod, HWPhase, HWThpState, HWUuid,
};
pub use crate::version::hw_core_version;
