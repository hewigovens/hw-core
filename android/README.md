# hw-core Android

Android library and sample app for hw-core, exposing Trezor hardware wallet communication via UniFFI bindings.

Call `System.loadLibrary("hwcore")` before any `uniffi.hwcore` call: the bindings load the library through JNA, which does not run its `JNI_OnLoad`, and that hook initializes btleplug. To build hw-core's Rust crates into your own native library instead of using this one, see [Embedding hw-core on Android](../docs/android-embedding.md).

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
./scripts/sync-bindings.sh --android            # debug
./scripts/sync-bindings.sh --android --release  # release
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

From repository root, you can do full sync + install + launch in one command:

```bash
just run-android
```

If multiple devices are connected, select one with:

```bash
ANDROID_SERIAL=<device-id> just run-android
```

## Use from another app (local Maven)

hw-core does not publish artifacts. To use the library from an app outside this repository, publish it to your local Maven repository (`~/.m2`):

```bash
just android-publish-local
```

This builds release native libraries for `arm64-v8a`, `armeabi-v7a` and `x86_64`, regenerates the Kotlin bindings, and publishes `dev.hewig.hwcore:hwcore:<version>`, where the version is the Rust workspace version (override it with `./gradlew :lib:publishToMavenLocal -PhwcoreVersion=<version>`). The AAR carries the native libraries, the patched btleplug Java classes and consumer R8 rules.

In the consuming app, add `mavenLocal()` to the repositories in `settings.gradle.kts` and depend on it:

```kotlin
dependencies {
    implementation("dev.hewig.hwcore:hwcore:0.1.1")
}
```

Then call `System.loadLibrary("hwcore")` before any `uniffi.hwcore` call and request the Bluetooth permissions, as described in [Embedding hw-core on Android](../docs/android-embedding.md#2-load-the-library-with-systemloadlibrary-first). Re-run `just android-publish-local` after updating hw-core.

## Sample App Flow

1. **Scan** — discovers nearby Trezor Safe 7 devices via BLE
2. **Connect/Pair** — establishes THP session and handles pairing prompt/confirmation
3. **Select Chain** — switch between ETH/BTC/SOL in the ready screen
4. **Get Address** — fetch chain-specific default-path address
5. **Sign Tx** — sign sample transactions for ETH/BTC/SOL
6. **Sign Message** — sign ETH/BTC messages and SOL off-chain messages (OCMS v1, signing key as sole signer)

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
