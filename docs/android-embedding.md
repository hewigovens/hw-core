# Embedding hw-core on Android

This guide is for Android apps that build hw-core's Rust crates (`hw-core`, `hw-wallet`, `trezor-connect`, `ble-transport`) into **their own** native library, for example a wallet that already ships one UniFFI `.so`. Apps that use hw-core's Kotlin library in [`android/lib`](../android/README.md) get all of this from that library and only need the [permissions](#4-request-bluetooth-permissions).

On Android, hw-core talks Bluetooth through [btleplug](https://github.com/deviceplug/btleplug), whose Android backend ("droidplug") is Java code driven from Rust over JNI. That Java code is not compiled into the `.so`, so the embedding app has to supply it, initialize it from `JNI_OnLoad`, and load the library in a way that runs `JNI_OnLoad`. The steps below mirror what hw-core's own library and sample app do; they are the path tested on real devices.

## 1. Initialize btleplug from your `JNI_OnLoad`

A shared library has one `JNI_OnLoad`. hw-core defines its own only in `hw-ffi` ([`crates/hw-ffi/src/platform/android.rs`](../crates/hw-ffi/src/platform/android.rs)), which embedding apps do not link, so yours must call `btleplug::platform::init` before any hw-core BLE call:

```rust
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    if vm.is_null() {
        return jni::sys::JNI_ERR;
    }
    // SAFETY: the JVM passes a valid JavaVM pointer; null was rejected above.
    let vm = unsafe { jni::JavaVM::from_raw(vm) };
    let result = vm.attach_current_thread(|env| {
        btleplug::platform::init(env).map_err(|err| err.to_string())
    });
    match result {
        Ok(()) => jni::sys::JNI_VERSION_1_6,
        Err(_) => jni::sys::JNI_ERR,
    }
}
```

Add the matching dependencies for the Android target. Use the btleplug version hw-core resolves (0.13.x at the time of writing, see the workspace `Cargo.toml`) so Cargo unifies on one copy, and the `jni` version that btleplug release uses (0.22 for btleplug 0.13):

```toml
[target.'cfg(target_os = "android")'.dependencies]
btleplug = "0.13.4"
jni = "0.22"
```

`init` registers btleplug's native methods and caches its Java classes and the global adapter. Without it, the first adapter lookup (for example `BleManager` scanning) panics with "Droidplug has not been initialized".

## 2. Load the library with `System.loadLibrary` first

UniFFI's Kotlin bindings load the library through JNA, which does not run `JNI_OnLoad`. Load it explicitly from app code before the first binding call, as the sample app does in [`MainActivity`](../android/sample-app/app/src/main/java/dev/hewig/hwcore/MainActivity.kt):

```kotlin
init {
    // Runs JNI_OnLoad, which initializes btleplug, before any BLE call.
    System.loadLibrary("yourlib")
}
```

Where you load it matters. During `init`, btleplug looks up its Java classes through the calling thread's context class loader and falls back to `FindClass`, which inside `JNI_OnLoad` uses the class loader of the code that called `System.loadLibrary`. Both are the app's class loader when the call comes from your app code (an `Activity`, `Application`, or a Kotlin `object` initializer). The classes are cached at this point, so later calls from Tokio worker threads work. From a thread that only has the system class loader, `init` cannot find btleplug's classes and `JNI_OnLoad` returns `JNI_ERR`, so `System.loadLibrary` throws.

## 3. Ship btleplug's Java sources, with hw-core's patch

btleplug's Java side lives in the btleplug crate source under `src/droidplug/java/src/main/java`, in two packages:

- `com.nonpolynomial.btleplug.android.impl` (adapter, peripheral, exceptions)
- `io.github.gedgygedgy.rust` (jni-utils futures, streams and callbacks)

Copy both into your Android module's `src/main/java`, from the same btleplug version your Rust build uses, then apply [`android/patches/btleplug-Peripheral.patch`](../android/patches/btleplug-Peripheral.patch). [`scripts/sync-bindings.sh`](../scripts/sync-bindings.sh) (`sync_android_java_support`) is the reference: it finds the crate under `~/.cargo/registry/src` (or `BTLEPLUG_RS_DIR`), copies both trees, and applies the patch with `git apply`.

The patch is not optional for THP traffic. On stock droidplug, notifications that arrive while no read is pending are dropped, and `WRITE_TYPE_NO_RESPONSE` writes can stall the command queue on stacks that never fire `onCharacteristicWrite`. The patch:

- buffers notifications per characteristic (up to 256) and completes pending reads from `onCharacteristicChanged` without holding the command queue;
- completes write-without-response immediately and retries a failed `writeCharacteristic` up to 8 times, 12 ms apart;
- fails pending reads with `NotConnectedException` and clears the buffers on unsubscribe and disconnect.

Re-check that the patch applies whenever you bump btleplug.

If you minify release builds, keep these classes: Rust finds them by name and registers native methods on them, so R8 must not rename or strip them. hw-core's library ships the same rules in [`consumer-rules.pro`](../android/lib/consumer-rules.pro), though its own builds run with `isMinifyEnabled = false`, so a minified build has not been exercised:

```proguard
-keep class com.nonpolynomial.btleplug.** { *; }
-keep class io.github.gedgygedgy.rust.** { *; }
```

## 4. Request Bluetooth permissions

Declare the permissions the sample app uses ([`AndroidManifest.xml`](../android/sample-app/app/src/main/AndroidManifest.xml)):

```xml
<uses-permission android:name="android.permission.BLUETOOTH" android:maxSdkVersion="30" />
<uses-permission android:name="android.permission.BLUETOOTH_ADMIN" android:maxSdkVersion="30" />
<uses-permission
    android:name="android.permission.BLUETOOTH_SCAN"
    android:usesPermissionFlags="neverForLocation" />
<uses-permission android:name="android.permission.BLUETOOTH_CONNECT" />
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-feature android:name="android.hardware.bluetooth_le" android:required="true" />
```

At runtime, request `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT` and `ACCESS_FINE_LOCATION` on Android 12 (API 31) and later, and `BLUETOOTH`, `BLUETOOTH_ADMIN` and `ACCESS_FINE_LOCATION` before that, and only start scanning once they are granted. hw-core's Android builds target API 28 as the minimum (`cargo ndk --platform 28`, `minSdk = 28`).

## 5. Build the native library

Cross-compile with [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk) for the ABIs you ship; hw-core builds `arm64-v8a`, `armeabi-v7a` and `x86_64` at platform 28:

```bash
cargo ndk --target arm64-v8a --platform 28 -- build --release -p yourlib
```

## Known pitfalls

- **Stale OS bond:** `btleplug error: Not connected` right after connecting usually means a stale Bluetooth bond to the Trezor; see [troubleshooting](troubleshooting.md#android).
- **Pairing file location:** if you persist pairing state with `FileStorage`, use a dedicated subdirectory such as `filesDir/hwcore/thp-host.json`. Android's `filesDir` is group-writable, and hw-core refuses to store credentials directly in it. The snapshot holds the host's static key and pairing credentials, so keep it out of backups and logs.
- **Logs:** logcat buffers rotate quickly on some devices; enlarge them with `adb logcat -G 16M`.
