# HWCoreKit (iOS/macOS)

`HWCoreKit` is a thin Swift wrapper around generated UniFFI bindings from `crates/hw-ffi`.

## What It Provides
- Device discovery (`discoverTrezor`)
- Session setup (`prepareChannelAndHandshake`)
- Pairing loop (`startPairing`, `submitPairingCode`, `confirmPairedConnection`)
- Wallet session creation (`createWalletSession`)
- Chain-agnostic address/sign flows (`getAddress`, `signTx`)
- Event stream (`events() -> AsyncStream<WalletEvent>`)
- Rust-native `HwCoreError` surfaced directly in Swift

## Sync Generated Bindings
From repo root:

```bash
just bindings
./scripts/sync-bindings.sh --apple
```

## Build Rust FFI for iOS Simulator
From repo root:

```bash
./scripts/sync-bindings.sh --apple --ios-sim-only
```

This produces:

```text
target/ios-sim/debug/libhwcore.dylib
```

`HWCoreKit` links this artifact on iOS simulator builds.

## Integrate in App
1. Add `apple/HWCoreKit` as a local Swift package dependency in Xcode.
2. Ensure your app can load the platform-compatible `libhwcore.dylib`:
   - macOS: `target/debug/libhwcore.dylib`
   - iOS simulator: `target/ios-sim/debug/libhwcore.dylib`
3. Add `NSBluetoothAlwaysUsageDescription` to your app Info.plist.
4. Use `HWCoreKit.create(...)` to initialize and begin workflow calls.

## Notes
- This scaffold is intentionally thin and keeps protocol-heavy logic in Rust.
- Logging is redacted and deterministic by default through the `WalletLogger` protocol.
