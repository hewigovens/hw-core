uniffi::setup_scaffolding!();

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    let init_result = (|| -> Result<(), String> {
        let vm = unsafe { jni::JavaVM::from_raw(vm) }.map_err(|err| err.to_string())?;
        let env = vm.get_env().map_err(|err| err.to_string())?;
        jni_utils::init(&env).map_err(|err| err.to_string())?;
        btleplug::platform::init(&env).map_err(|err| err.to_string())
    })();

    if let Err(err) = init_result {
        eprintln!("hwcore JNI_OnLoad init failed: {err}");
        return jni::sys::JNI_ERR;
    }

    jni::sys::JNI_VERSION_1_6
}

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
    SessionRetryPolicy, SessionState, SignMessageRequest, SignMessageResult, SignTxRequest,
    SignTxResult, SignTypedDataRequest, SignTypedDataResult, SignatureEncoding, ThpState, Uuid,
    WorkflowEvent, WorkflowEventKind, chain_config, host_config_new, session_retry_policy_default,
};
pub use crate::version::hw_core_version;
