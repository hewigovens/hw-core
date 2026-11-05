# HWCoreKit (iOS/macOS)

`HWCoreKit` is a thin Swift wrapper around generated UniFFI bindings from `crates/hw-ffi`.

## What It Provides
- Trezor discovery (`discoverTrezor`) and Ledger model discovery (`discover(vendor:)`)
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
`just bindings` and the sample app recipes prepare a debug build of the same package on macOS.
See the [iOS and macOS integration guide](https://github.com/hewigovens/hw-core/blob/main/docs/apple-integration.md) for
platform requirements, Bluetooth permissions, storage and workflow examples.

## Ledger

Call `discover(vendor: .ledgerStax)` (or `.ledgerNanoX` / `.ledgerFlex`), then
`connect(device:)`. The returned `WalletSession` supports the same Ethereum/Solana/Bitcoin `getAddress`,
`signTx`, and `signMessage` requests, plus Ethereum `signTypedData`. Open the corresponding
Ethereum, Solana, or Bitcoin app on the Ledger first.
Bitcoin transaction signing currently supports single-account BIP84 inputs with full reference transactions.
Trezor pairing, nonce, and features are unsupported.
Ledger's `events()` stream finishes immediately; use operation results/errors for status.
After cancelling a Ledger request, reject any remaining prompt, disconnect, and rescan.
See [Ledger support](../../docs/ledger.md) for tested hardware and signing limitations.

## Notes
- This scaffold is intentionally thin and keeps protocol-heavy logic in Rust.
- Logging is redacted and deterministic by default through the `WalletLogger` protocol.
