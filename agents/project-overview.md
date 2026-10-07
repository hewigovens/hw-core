# Project Overview

hw-core is a Rust workspace for host-to-hardware crypto wallet communication. The first target is Trezor Safe 7 over BLE using the Trezor Host Protocol (THP). The transport/core stack is designed to be shared across wallet vendors.

## Crate Architecture

```
thp-proto        Prost-generated protobuf types from vendored messages-thp.proto
ble-transport    BLE primitives via btleplug (scanning, connection, I/O)
trezor-connect   Host-facing THP workflow API + BLE backend
hw-wallet        Shared wallet orchestration for CLI and FFI
hw-chain         Chain enum, ChainConfig (code, SLIP-44, default BIP32 path)
hw-ffi           UniFFI 0.32 cdylib for mobile/desktop (Swift/Kotlin bindings)
hw-cli           Interactive CLI using clap
```

## Dependency Graph

```
thp-proto ────────────────┐
hw-chain ─────────────────┼─→ trezor-connect ──→ hw-wallet ──┬─→ hw-ffi
ble-transport ────────────┘                                  └─→ hw-cli
```

`ble-transport` is optional in `trezor-connect` (`ble` feature). `hw-wallet` also depends on `hw-chain` and `ble-transport`; `hw-ffi` and `hw-cli` depend on `trezor-connect` and `ble-transport` directly.

## Feature Flags

- `ble` on `trezor-connect`: enables BLE transport (btleplug, Noise handshake, pairing)
- `backend-btleplug` on `ble-transport`: btleplug backend (default-on)
- `trezor-safe7` on `ble-transport`: Trezor Safe 7 device profile

## Key Design Patterns

- **`ThpBackend` trait** (`trezor-connect/src/thp/backend.rs`): Async trait defining all THP protocol operations. `BleBackend` is the concrete implementation. Tests use `MockBackend`.
- **Workflow state machine** (`trezor-connect/src/thp/workflow.rs`): `ThpWorkflow<B: ThpBackend>` drives Handshake → Pairing → Paired lifecycle. State held in a `ThpState` field on the workflow.
- **`PairingController` trait** (`trezor-connect/src/thp/types.rs`): Async trait for custom pairing UX. CLI implements `CliPairingController`.
- **`ThpStorage` trait** (`trezor-connect/src/thp/storage/mod.rs`): `FileStorage` persists host credentials as JSON. Tests use `InMemoryStorage`.
- **`BleProfile`** (`ble-transport`): Pluggable wallet vendor support (currently Trezor Safe 7).

## License

Apache-2.0
