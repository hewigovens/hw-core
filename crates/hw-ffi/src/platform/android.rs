use super::init_platform_tracing_once;

#[derive(Debug, thiserror::Error)]
enum JniInitError {
    #[error("{0}")]
    Jni(#[from] jni::errors::Error),
    #[error("{0}")]
    Btleplug(String),
}

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
