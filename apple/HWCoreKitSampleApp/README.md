# HWCoreKitSampleApp

A minimal SwiftUI sample app (macOS + iOS) that exercises the `HWCoreKit` API.

## What It Demonstrates
- Creating an `HWCoreKit` instance
- BLE device discovery
- Workflow-state driven pair/connect transitions from Rust state machine
- Pair-only flow (`pair --force` equivalent) and connect-ready flow
- Pairing code entry via SwiftUI alert
- Address retrieval for ETH/BTC/SOL
- Signing requests for ETH/BTC/SOL (basic BTC request types)
- Event stream consumption (`session.events()`)
- App lifecycle recovery path (background disconnect + foreground reconnect attempt)

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

If dynamic library loading fails at runtime, set:

```bash
export DYLD_LIBRARY_PATH="$(pwd)/target/debug"
```

## Run (iOS)
1. From repository root, generate bindings and iOS-simulator Rust FFI:
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
- iOS simulator links statically from `target/ios-sim/debug/libhw_ffi.a`.
- iOS devices link statically from `target/aarch64-apple-ios/debug/libhw_ffi.a`.
- `just bindings` builds these iOS static libraries automatically on macOS.

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
