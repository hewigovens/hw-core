# HWCoreKit (iOS/macOS)

`HWCoreKit` is a thin Swift wrapper around generated UniFFI bindings from `crates/hw-ffi`.

## What It Provides
- Device discovery (`discoverTrezor`)
- Session setup (`prepareChannelAndHandshake`)
- Pairing loop (`startPairing`, `submitPairingCode`, `confirmPairedConnection`)
- Wallet session creation (`createWalletSession`)
- Ethereum flows (`getEthereumAddress`, `signEthereumTx`)
- Event stream (`events() -> AsyncStream<WalletEvent>`)
- Typed Swift errors mapped from Rust (`HWCoreKitError`)

## Sync Generated Bindings
From repo root:

```bash
just bindings
./apple/HWCoreKit/Scripts/sync-bindings.sh
```

## Integrate in App
1. Add `apple/HWCoreKit` as a local Swift package dependency in Xcode.
2. Ensure your app can load `libhw_ffi.dylib` from `target/debug` (or adjust linker settings for your build output path).
3. Add `NSBluetoothAlwaysUsageDescription` to your app Info.plist.
4. Use `HWCoreKit.create(...)` to initialize and begin workflow calls.

## Notes
- This scaffold is intentionally thin and keeps protocol-heavy logic in Rust.
- Logging is redacted and deterministic by default through the `WalletLogger` protocol.
