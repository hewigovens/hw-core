uniffi::setup_scaffolding!();

mod ble;
mod errors;
mod platform;
mod types;
mod version;

pub use crate::ble::{
    BleDiscoveredDevice, BleManagerHandle, BleSessionHandle, BleWorkflowHandle, HostStorage,
    HostStorageError,
};
pub use crate::errors::HWCoreError;
pub use crate::types::{
    AccessListEntry, AddressResult, BitcoinRefTx, BitcoinRefTxInput, BitcoinRefTxOutput,
    BitcoinSignTxRequest, BitcoinTxInput, BitcoinTxOutput, BleDeviceInfo, ButtonRequest,
    ButtonRequestCode, Chain, ChainConfig, DeviceFeatures, GetAddressRequest, HostConfig,
    KnownCredential, PairingMethod, PairingProgress, PairingProgressKind, PairingPrompt,
    SessionHandshakeState, SessionPhase, SessionRetryPolicy, SessionState, SignMessageRequest,
    SignMessageResult, SignTxRequest, SignTxResult, SignTypedDataRequest, SignTypedDataResult,
    SignatureEncoding, Uuid, WorkflowEvent, WorkflowEventKind, chain_config, host_config_new,
    session_retry_policy_default,
};
pub use crate::version::hw_core_version;
