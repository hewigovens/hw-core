# HWCoreKitSampleApp

A minimal macOS SwiftUI sample app that exercises the `HWCoreKit` API.

## What It Demonstrates
- Creating an `HWCoreKit` instance
- BLE device discovery
- Connect + THP prepare handshake
- Pairing code submission and paired-connection confirmation
- Wallet session creation
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

If dynamic library loading fails at runtime, set:

```bash
export DYLD_LIBRARY_PATH="$(pwd)/target/debug"
```
