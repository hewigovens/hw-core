# HWCoreKitSampleApp

A minimal macOS SwiftUI sample app that exercises the `HWCoreKit` API.

## What It Demonstrates
- Creating an `HWCoreKit` instance
- BLE device discovery
- Workflow-state driven pair/connect transitions from Rust state machine
- Pair-only flow (`pair --force` equivalent) and connect-ready flow
- Pairing code entry via SwiftUI alert
- Ethereum address retrieval
- Ethereum transaction signing
- Event stream consumption (`session.events()`)

## Run
From repository root:

```bash
just bindings
swift run --package-path apple/HWCoreKitSampleApp
```

On first run, macOS should prompt for Bluetooth access.
`swift run` starts a GUI app and stays attached to the process until you quit the window.
If the process exits with `SIGABRT`/code `134`, clean the package build artifacts and run again so the embedded `Info.plist` is rebuilt.

If dynamic library loading fails at runtime, set:

```bash
export DYLD_LIBRARY_PATH="$(pwd)/target/debug"
```
