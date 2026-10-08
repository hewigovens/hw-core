uniffi::setup_scaffolding!();

#[cfg(all(any(target_os = "android", target_vendor = "apple"), debug_assertions))]
const DEFAULT_TRACING_DIRECTIVES: &str =
    "info,hw_ffi=debug,hw_wallet=debug,trezor_connect=debug,trezor_thp=debug,ble_transport=debug";

#[cfg(all(any(target_os = "android", target_vendor = "apple"), debug_assertions))]
fn default_tracing_filter() -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;

    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_TRACING_DIRECTIVES))
}

// `try_init` also installs the `log` bridge, so `trezor-thp` records reach these subscribers.
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

#[cfg(all(target_vendor = "apple", debug_assertions))]
fn init_apple_tracing_once() {
    use std::sync::Once;
    use tracing_subscriber::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = tracing_subscriber::registry()
            .with(default_tracing_filter())
            .with(
                fmt::layer()
                    .with_ansi(false)
                    .with_target(true)
                    .with_writer(std::io::stderr),
            )
            .try_init();
    });
}

pub(crate) fn init_platform_tracing_once() {
    #[cfg(all(target_os = "android", debug_assertions))]
    init_android_tracing_once();
    #[cfg(all(target_vendor = "apple", debug_assertions))]
    init_apple_tracing_once();
}

#[cfg(target_os = "android")]
#[derive(Debug, thiserror::Error)]
enum JniInitError {
    #[error("{0}")]
    Jni(#[from] jni::errors::Error),
    #[error("{0}")]
    Btleplug(String),
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
/// # Safety
/// A non-null `vm` must be a valid `JavaVM` pointer. A null pointer returns `JNI_ERR`.
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    if vm.is_null() {
        eprintln!("hwcore JNI_OnLoad init failed: null JavaVM");
        return jni::sys::JNI_ERR;
    }

    let init_result = (|| -> Result<(), String> {
        init_platform_tracing_once();

        // SAFETY: null was rejected above.
        let vm = unsafe { jni::JavaVM::from_raw(vm) };
        vm.attach_current_thread(|env| {
            btleplug::platform::init(env).map_err(|err| JniInitError::Btleplug(err.to_string()))?;
            #[cfg(debug_assertions)]
            tracing::info!("hwcore JNI_OnLoad complete; Rust tracing enabled");
            Ok(())
        })
        .map_err(|err: JniInitError| err.to_string())?;
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
    HostConfig, KnownCredential, PairingMethod, PairingProgress, PairingProgressKind,
    PairingPrompt, SessionHandshakeState, SessionPhase, SessionRetryPolicy, SessionState,
    SignMessageRequest, SignMessageResult, SignTxRequest, SignTxResult, SignTypedDataRequest,
    SignTypedDataResult, SignatureEncoding, Uuid, WorkflowEvent, WorkflowEventKind, chain_config,
    host_config_new, session_retry_policy_default,
};
pub use crate::version::hw_core_version;

#[cfg(all(test, target_vendor = "apple", debug_assertions))]
mod tests {
    #[test]
    fn platform_tracing_routes_trezor_thp_log_records_at_debug() {
        super::init_platform_tracing_once();

        assert!(log::log_enabled!(target: "trezor_thp::channel::host", log::Level::Debug));
        assert!(!log::log_enabled!(target: "trezor_thp::channel::host", log::Level::Trace));
        assert!(!log::log_enabled!(target: "unrelated_crate", log::Level::Debug));
    }
}
