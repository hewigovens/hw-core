# Integrating hw-core on iOS and macOS

This guide covers two ways to use hw-core from an Apple app:

- **HWCoreKit:** the Swift wrapper in [`apple/HWCoreKit`](../apple/HWCoreKit/README.md), linked against an `HWCore.xcframework` you build locally from this repository.
- **Embedding the crates:** building hw-core's Rust crates (`hw-core`, `hw-wallet`, `trezor-connect`, `ble-transport`) into your own Rust library and exposing them through your own bindings.

hw-core does not publish prebuilt binaries; both paths build from source. Steps 3–6 apply to both.

## 1. Build the xcframework

On a Mac with Xcode and rustup, from the repository root:

```bash
just xcframework
```

[`scripts/build-xcframework.sh`](../scripts/build-xcframework.sh) builds release `hw-ffi` static libraries for iOS (`aarch64-apple-ios`), the iOS simulator (`aarch64-apple-ios-sim`, `x86_64-apple-ios`) and macOS (`aarch64-apple-darwin`, `x86_64-apple-darwin`), then writes:

- `target/xcframework/HWCore.xcframework`, the static library with the C header and module map (module `libhwcore`)
- `target/xcframework/swift/HWCoreFFI.swift`, the UniFFI Swift bindings for that exact build

Deployment targets default to iOS 16.0 and macOS 13.0; override them with `IOS_DEPLOYMENT_TARGET` and `MACOS_DEPLOYMENT_TARGET`. The bindings and the library must come from the same build, so rebuild both whenever you update hw-core.

## 2. Package HWCoreKit for your app

`apple/HWCoreKit/Package.swift` links `target/debug` with unsafe linker flags for development inside this repository, so don't depend on it directly. Instead, vendor a small local package into your app's repository:

```text
HWCoreKit/
  Package.swift
  HWCore.xcframework            # from target/xcframework
  Sources/HWCoreFFI/HWCoreFFI.swift   # from target/xcframework/swift
  Sources/HWCoreKit/*.swift           # from apple/HWCoreKit/Sources/HWCoreKit
```

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HWCoreKit",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "HWCoreKit", targets: ["HWCoreKit"])],
    targets: [
        .binaryTarget(name: "libhwcore", path: "HWCore.xcframework"),
        .target(name: "HWCoreFFI", dependencies: ["libhwcore"], path: "Sources/HWCoreFFI"),
        .target(
            name: "HWCoreKit",
            dependencies: ["HWCoreFFI"],
            path: "Sources/HWCoreKit",
            linkerSettings: [.linkedFramework("CoreBluetooth"), .linkedLibrary("iconv")]
        ),
    ]
)
```

Add it to your Xcode project as a local package and `import HWCoreKit`; HWCoreKit re-exports the request, state and error types its API uses, so apps don't import `HWCoreFFI` directly. This layout was checked by building it for macOS, the iOS simulator and an iOS device.

If you embed the crates instead, build your own library for the same five targets and combine them with `xcodebuild -create-xcframework` exactly as the script does. Your Rust library's static archive needs the same system libraries (`-framework CoreBluetooth -framework Foundation -liconv`; `cargo rustc --crate-type staticlib -- --print native-static-libs` lists them). Unlike Android, btleplug needs no initialization call on Apple platforms.

## 3. Declare Bluetooth usage

Add `NSBluetoothAlwaysUsageDescription` to the app's Info.plist on both iOS and macOS; without it, iOS terminates the app the first time hw-core touches Bluetooth. `HWCoreKit.create` checks for the key on macOS and throws a `Validation` error when it is missing. The sample apps also set the older `NSBluetoothPeripheralUsageDescription`.

A sandboxed macOS app also needs the `com.apple.security.device.bluetooth` entitlement. hw-core does nothing special for background execution; if your app needs Bluetooth while backgrounded, add the `bluetooth-central` background mode and expect to reconnect when it returns (stale pairing and reconnect after backgrounding are tracked in [#107](https://github.com/hewigovens/hw-core/issues/107)).

## 4. Keep pairing state in the Keychain

After pairing, hw-core saves a snapshot holding this host's static private key and the pairing credentials the device issued. Whoever holds it can connect to the paired Trezor as this host without pairing again (requests still need on-device confirmation), so store it in the Keychain rather than a file. Implement `HostStorage` and pass it in `HWCoreConfig`; it takes precedence over `storagePath`:

```swift
import HWCoreKit
import Security

final class KeychainHostStorage: HostStorage, @unchecked Sendable {
    private let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.example.wallet.trezor-host",
        kSecAttrAccount as String: "thp-host",
    ]

    func load() throws -> Data? {
        var item: CFTypeRef?
        var lookup = query
        lookup[kSecReturnData as String] = true
        switch SecItemCopyMatching(lookup as CFDictionary, &item) {
        case errSecSuccess: return item as? Data
        case errSecItemNotFound: return nil
        case let status: throw HostStorageError.Failed(reason: "Keychain read failed: \(status)")
        }
    }

    func persist(snapshot: Data) throws {
        let update = [kSecValueData as String: snapshot] as CFDictionary
        var status = SecItemUpdate(query as CFDictionary, update)
        if status == errSecItemNotFound {
            var add = query
            add[kSecValueData as String] = snapshot
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(add as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw HostStorageError.Failed(reason: "Keychain write failed: \(status)")
        }
    }
}
```

The snapshot is opaque bytes; store and return it unchanged. Apps embedding the crates implement `trezor_connect::thp::ThpStorage` in Rust instead.

## 5. Connect, pair and read an address

```swift
let kit = try await HWCoreKit.create(
    config: HWCoreConfig(hostName: "My iPhone", appName: "Example Wallet", hostStorage: KeychainHostStorage())
)
guard let device = try await kit.discoverTrezor().first else { return }
let session = try await kit.connect(device: device)

switch try await session.prepareChannelAndHandshake() {
case .ready:
    break
case .pairingRequired(let prompt):
    // Show prompt.message and ask for the 6-digit code from the Trezor screen.
    _ = try await session.submitPairingCode(code)
case .connectionConfirmationRequired:
    _ = try await session.confirmPairedConnection()
}
try await session.createWalletSession()

let features = try await session.getFeatures()   // device id, label, model, firmware version
let address = try await session.getAddress(chain: .ethereum, showOnDevice: true).address
```

`DeviceFeatures.deviceId` is the stable identity to bind a wallet to; `BleDeviceInfo.id` is the OS Bluetooth identifier and differs between phones. To pair by QR code or NFC instead of the code, call `selectPairingMethod(.qrCode)` or `selectPairingMethod(.nfc)` after `pairingRequired` and then `submitPairingQrTag` or `submitPairingNfcTag`; for NFC, the returned prompt's `nfcData` is what the app hands to the device.

## 6. Follow device prompts, cancel and handle errors

`session.events()` streams workflow events. A `.buttonRequest` event arrives only when the Trezor is actually showing a prompt, with a typed `ButtonRequestCode` (`.signTx`, `.confirmOutput`, `.pinEntry`, `.passphraseEntry`, …), so the app can switch its UI to "Review and approve on your Trezor" at the right moment:

```swift
Task {
    for await event in session.events() {
        if let prompt = event.buttonRequest {
            showReviewOnDevice(prompt.code)
        }
    }
}
```

`session.cancel()` cancels the prompt the device is showing for the running call: hw-core sends `Cancel` on the open channel, the call throws `ActionCancelled`, and the device returns to its home screen without a new handshake. `disconnect()` tears the connection down instead.

Errors are typed `HwCoreError` cases, so each can map to its own screen without matching message text:

```swift
do {
    let result = try await session.signTx(request)
} catch HwCoreError.ActionCancelled {
    // Rejected on the device, or cancelled from the app.
} catch HwCoreError.DeviceLocked {
    // Ask the user to unlock the Trezor.
} catch HwCoreError.PairingRequired {
    // The device no longer knows this host: pair again.
} catch HwCoreError.Disconnected, HwCoreError.Timeout {
    // The channel was dropped; reconnect before the next request.
}
```

Other cases are `DeviceBusy`, `ConnectionConfirmationRequired`, `Unsupported` (the firmware does not support the request), `Validation`, `Ble`, `Workflow`, `Device` and `Unknown`. After a timeout or disconnect, call `connectReady` (or redo `prepareChannelAndHandshake`) before the next request.

The [macOS and iOS sample apps](../apple/HWCoreKitSampleApp) exercise the same flow end to end inside this repository.
