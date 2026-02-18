# CLAUDE.md

This file provides guidance to AI coding agents working with code in this repository.

## Project

hw-core is a Rust workspace for host-to-hardware crypto wallet communication. The first target is Trezor Safe 7 over BLE using the Trezor Host Protocol (THP). The transport/core stack is designed to be shared across wallet vendors.

## Source of Truth for Behavior

- When debugging protocol/flow mismatches, always check the Trezor Suite implementation first:
  - `~/workspace/github/trezor-suite`
- Treat Trezor Suite app behavior as the reference for:
  - request payload shapes
  - derivation path/account handling
  - signing request construction
  - user-facing pairing/connect/address/sign flows

## Build Commands

The project uses `just` as a task runner. Key commands:

```bash
just build            # cargo build --workspace
just test             # cargo test --workspace
just lint             # cargo clippy --workspace --all-targets --all-features -- -D warnings
just fmt              # cargo fmt --all
just ci               # fmt check + clippy + test (mirrors CI)
just bindings         # build hw-ffi and generate Swift/Kotlin bindings
```

Run a single test: `cargo test -p <crate-name> <test_name>`

Run the CLI: `cargo run -p hw-cli -- <command>` (e.g., `scan`, `pair`, `address eth`)

On Linux, BLE requires: `sudo apt-get install -y libdbus-1-dev pkg-config`

## Feature Flags

- `ble` on `trezor-connect`: enables BLE transport (btleplug, Noise handshake, pairing)
- `backend-btleplug` on `ble-transport`: btleplug backend (default-on)
- `trezor-safe7` on `ble-transport`: Trezor Safe 7 device profile

## Crate Architecture

```
thp-codec        Wire framing (length-prefix, CRC, chunking)
thp-crypto       Noise XX + CPace crypto primitives
thp-core         Async THP session state machine (depends on codec, crypto)
thp-proto        Prost-generated protobuf types from vendored messages-thp.proto
ble-transport    BLE primitives via btleplug (scanning, connection, I/O)
trezor-connect   Host-facing THP workflow API + BLE backend (depends on core, proto, ble-transport)
hw-wallet        Shared wallet orchestration for CLI and FFI (depends on trezor-connect, ble-transport)
hw-ffi           UniFFI cdylib for mobile/desktop (Swift/Kotlin bindings)
hw-cli           Interactive CLI using clap (depends on hw-wallet)
```

## Key Design Patterns

**Backend trait**: `ThpBackend` (async trait in `trezor-connect/src/thp/backend.rs`) defines all THP protocol operations. `BleBackend` is the concrete implementation. Tests use `MockBackend` with `parking_lot::Mutex` for call tracking.

**Workflow state machine**: `ThpWorkflow<B: ThpBackend>` drives THP lifecycle through phases: Handshake -> Pairing -> Paired. State is held in `ThpState` using `parking_lot::Mutex` for interior mutability.

**PairingController trait**: Async trait (`trezor-connect/src/thp/types.rs`) allowing custom pairing UX. CLI implements `CliPairingController` for interactive terminal prompts.

**Storage**: `ThpStorage` trait with `FileStorage` persisting host credentials as JSON at `~/.hw-core/thp-host.json`. Tests use `InMemoryStorage`.

**Error handling**: Layered `thiserror` enums at each crate boundary. CLI uses `anyhow::Result` at the top level. FFI flattens all errors to string messages via `HWCoreError`.

**BLE device profiles**: `BleProfile` in `ble-transport` enables pluggable wallet vendor support (currently Trezor Safe 7).

## Conventions

- Async runtime: Tokio (multi-thread in CLI)
- Protobuf: vendored proto compiled via `prost-build` + `protoc-bin-vendored` in `thp-proto/build.rs`
- FFI: UniFFI 0.30 with `#[derive(uniffi::Object)]` and `#[uniffi::export]` macros
- Workspace lints: `rust.unused = "allow"`; clippy runs with `-D warnings`
- License: Apache-2.0 OR MIT
- Unit tests are inline in source files; `proptest` used in thp-codec; `tempfile` for storage tests

## Development Status

See [docs/roadmap.md](docs/roadmap.md) for the roadmap and [docs/cli-wallet-v1.md](docs/cli-wallet-v1.md) for the detailed v1 task tracker.
