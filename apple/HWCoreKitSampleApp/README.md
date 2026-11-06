# HWCoreKitSampleApp

A minimal SwiftUI sample app (macOS + iOS) that exercises the `HWCoreKit` API.

## What It Demonstrates
- Creating an `HWCoreKit` instance
- Direct BLE discovery for Trezor Safe 7 and Ledger Stax/Nano X/Flex
- Workflow-state driven pair/connect transitions from Rust state machine
- Pair-only flow (`pair --force` equivalent) and connect-ready flow
- Pairing code entry via SwiftUI alert
- Address retrieval and transaction/message signing for Ledger and Trezor ETH/BTC/SOL (Ledger BTC transactions currently require single-account BIP84 inputs)
- Signing requests for ETH/BTC/SOL (basic BTC request types)
- Event stream consumption (`session.events()`)
- App lifecycle recovery path (background disconnect + foreground reconnect attempt)

For Ledger, select the model in **Wallet**, open Ethereum, Solana, or Bitcoin on the device, then scan and connect. For EIP-712, enable **EIP-712 typed data** in message inputs, edit JSON, and use **Sign Msg**. Pair-only, nonce, and chunkify controls are Trezor-specific. See [Ledger support](../../docs/ledger.md) for limitations and cancellation/reconnect behavior.

## Run (macOS)
From repository root:

```bash
just bindings
swift run --package-path apple/HWCoreKitSampleApp
```

Shortcut:

```bash
just run-mac
```

On first run, macOS should prompt for Bluetooth access.
`swift run` starts a GUI app and stays attached to the process until you quit the window.
If the process exits with `SIGABRT`/code `134`, clean the package build artifacts and run again so the embedded `Info.plist` is rebuilt.

## Run (iOS)
1. From repository root, prepare the packaged Apple SDK and simulator project:
   ```bash
   just build-ios
   ```
2. Open `apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj` in Xcode.
3. Select the `HWCoreKitSampleAppiOS` scheme and an iOS simulator destination.
4. Build and run.

Shortcut:

```bash
just run-ios
```

Note:
- The SwiftUI view and view model are shared between macOS and iOS.
- All Apple destinations link the static `HWCore.xcframework` through SwiftPM.
- `just bindings` prepares a debug build of the framework and matching bindings on macOS.
- `just xcframework` also creates a portable `target/xcframework/HWCoreKit` package.

## iOS UI Tests
Run iOS UI smoke tests:

```bash
just test-ios-ui
```

This generates `apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj` from `project-ios.yml` and runs a simulator smoke suite that validates launch, core controls, and scan interaction stability.

If you only want to validate UI-test build wiring without executing tests:

```bash
just build-ios-ui
```

## macOS UI Tests
Run the macOS UI smoke test target:

```bash
just test-mac-ui
```

This generates `apple/HWCoreKitSampleApp/HWCoreKitSampleAppMac.xcodeproj` from `project-mac.yml` and runs a basic XCUITest that validates launch + key workflow controls.

If you only want to validate build wiring (without executing the UI runner), use:

```bash
just build-mac-ui
```

Note: macOS UI tests require Automation accessibility permissions. If test execution fails with `Timed out while enabling automation mode`, grant Terminal/Codex + `HWCoreKitSampleAppMacUITests-Runner` in System Settings > Privacy & Security > Accessibility, then rerun `just test-mac-ui`.
