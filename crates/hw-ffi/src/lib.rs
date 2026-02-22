uniffi::setup_scaffolding!();

#[cfg(all(target_os = "android", debug_assertions))]
fn default_tracing_filter() -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;

    EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,hw_ffi=debug,hw_wallet=debug,trezor_connect=debug,ble_transport=debug")
    })
}

#[cfg(all(target_os = "android", debug_assertions))]
fn init_android_tracing_once() {
    use std::sync::Once;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = default_tracing_filter();
        match tracing_android::layer("hwcore-rs") {
            Ok(android_layer) => {
                let _ = tracing_subscriber::registry()
                    .with(filter)
                    .with(android_layer)
                    .try_init();
            }
            Err(_) => {
                let _ = tracing_subscriber::registry()
                    .with(filter)
                    .with(
                        fmt::layer()
                            .with_ansi(false)
                            .with_target(true)
                            .without_time(),
                    )
                    .try_init();
            }
        }
    });
}

pub(crate) fn init_platform_tracing_once() {
    #[cfg(all(target_os = "android", debug_assertions))]
    init_android_tracing_once();
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    let init_result = (|| -> Result<(), String> {
        init_platform_tracing_once();

        let vm = unsafe { jni::JavaVM::from_raw(vm) }.map_err(|err| err.to_string())?;
        let env = vm.get_env().map_err(|err| err.to_string())?;
        jni_utils::init(&env).map_err(|err| err.to_string())?;
        btleplug::platform::init(&env).map_err(|err| err.to_string())?;
        #[cfg(debug_assertions)]
        tracing::info!("hwcore JNI_OnLoad complete; Rust tracing enabled");
        Ok(())
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
