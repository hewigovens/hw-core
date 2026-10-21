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

## Build and Integrate

On a Mac with Xcode and Rust, run `just xcframework` from the repository root.
This builds the release XCFramework and matching Swift bindings, refreshes this
local package, and writes a portable package to `target/xcframework/HWCoreKit`.
Copy that entire generated directory into another app repository and add it as a
local Swift package dependency. The consumer does not need Rust or this checkout.

`Package.swift` uses a local `binaryTarget` and requires no unsafe linker flags.
Generated artifacts are not committed; build before resolving a fresh checkout.
Existing `just bindings` and sample app recipes prepare the same package on macOS.
See the [iOS and macOS integration guide](../../docs/apple-integration.md) for
platform requirements, Bluetooth permissions, storage and workflow examples.

## Notes
- This scaffold is intentionally thin and keeps protocol-heavy logic in Rust.
- Logging is redacted and deterministic by default through the `WalletLogger` protocol.
