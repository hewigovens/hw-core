uniffi::setup_scaffolding!();

mod ble;
mod errors;
mod types;
mod version;

pub use crate::ble::{BleDiscoveredDevice, BleManagerHandle, BleSessionHandle, BleWorkflowHandle};
pub use crate::errors::HWCoreError;
pub use crate::types::{
    HWBleDeviceInfo, HWChain, HWEthAccessListEntry, HWGetAddressRequest, HWGetAddressResult,
    HWHandshakeCache, HWHostConfig, HWKnownCredential, HWPairingMethod, HWPairingProgress,
    HWPairingProgressKind, HWPairingPrompt, HWPhase, HWSignEthTxRequest, HWSignEthTxResult,
    HWThpState, HWUuid, HWWorkflowEvent, HWWorkflowEventKind, host_config_new,
};
pub use crate::version::hw_core_version;
