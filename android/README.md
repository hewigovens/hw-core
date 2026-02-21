# hw-core Android

Android library and sample app for hw-core, exposing Trezor hardware wallet communication via UniFFI bindings.

## Structure

```
android/
  build.gradle.kts          Root Gradle config
  settings.gradle.kts        Workspace settings
  lib/                       Android library module (UniFFI bindings)
    src/main/java/uniffi/    Generated Kotlin bindings
    src/main/jniLibs/        Native .so files (per-ABI)
  sample-app/
    app/                     Sample Android app (Compose UI)
  scripts/
    build-rust.sh            Cross-compile Rust + generate bindings
```

## Prerequisites

1. Android NDK installed (set `ANDROID_NDK_HOME`).
2. Rust Android targets:
   ```bash
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
3. `cargo-ndk`:
   ```bash
   cargo install cargo-ndk
   ```

## Building

### 1. Build native libraries and generate bindings

```bash
./android/scripts/build-rust.sh          # debug
./android/scripts/build-rust.sh --release  # release
```

This cross-compiles `hw-ffi` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`,
copies the `.so` files into `lib/src/main/jniLibs/`, and regenerates the
Kotlin bindings in `lib/src/main/java/uniffi/`.

### 2. Open in Android Studio

Open the `android/` directory in Android Studio. The project includes:

- `:lib` — Android library with UniFFI bindings and native `.so` files
- `:sample-app:app` — Sample app consuming the library

### 3. Run the sample app

Build and run `sample-app:app` on a physical Android device with Bluetooth.

## Sample App Flow

1. **Scan** — discovers nearby Trezor Safe 7 devices via BLE
2. **Connect** — establishes THP session (Noise XX handshake)
3. **Pair** — enter 6-digit code shown on Trezor + confirm connection
4. **Get Address** — retrieves ETH address (`m/44'/60'/0'/0/0`)
5. **Sign Tx** — signs a sample EIP-1559 transaction (0 ETH to `0xdead`)

## API Surface

The library exposes the following via `uniffi.hwcore.*`:

| Type | Description |
|------|-------------|
| `BleManagerHandle` | BLE device discovery |
| `BleDiscoveredDevice` | Discovered device handle |
| `BleWorkflowHandle` | THP session state machine |
| `GetAddressRequest` | Address derivation request |
| `SignTxRequest` | Transaction signing request |
| `HwCoreException` | Error hierarchy (Ble, Workflow, Device, Validation, Timeout) |
| `hwCoreVersion()` | Library version string |
| `hostConfigNew()` | Create host configuration |
| `chainConfig()` | Get chain-specific config (path, slip44) |
