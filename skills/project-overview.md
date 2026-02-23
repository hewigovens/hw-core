# Project Overview

hw-core is a Rust workspace for host-to-hardware crypto wallet communication. The first target is Trezor Safe 7 over BLE using the Trezor Host Protocol (THP). The transport/core stack is designed to be shared across wallet vendors.

## Crate Architecture

```
thp-crypto       Noise XX crypto primitives + wire framing (CipherSuite trait, CRC32, chunking)
thp-core         Async THP session state machine (uses snow crate for Noise XX)
thp-proto        Prost-generated protobuf types from vendored messages-thp.proto
ble-transport    BLE primitives via btleplug (scanning, connection, I/O)
trezor-connect   Host-facing THP workflow API + BLE backend
hw-wallet        Shared wallet orchestration for CLI and FFI
hw-chain         Chain enum + SLIP-44 coin type constants
hw-ffi           UniFFI 0.31 cdylib for mobile/desktop (Swift/Kotlin bindings)
hw-cli           Interactive CLI using clap
```

## Dependency Graph

```
thp-crypto ─┬─→ thp-core ─┐
            │              ├─→ trezor-connect ─┬─→ hw-wallet ─┬─→ hw-ffi
thp-proto ──┘              │                   │              └─→ hw-cli
ble-transport ─────────────┘                   │
hw-chain ──────────────────────────────────────┘
```

## Feature Flags

- `ble` on `trezor-connect`: enables BLE transport (btleplug, Noise handshake, pairing)
- `backend-btleplug` on `ble-transport`: btleplug backend (default-on)
- `trezor-safe7` on `ble-transport`: Trezor Safe 7 device profile

## Key Design Patterns

- **`ThpBackend` trait** (`trezor-connect/src/thp/backend.rs`): Async trait defining all THP protocol operations. `BleBackend` is the concrete implementation. Tests use `MockBackend`.
- **Workflow state machine** (`trezor-connect/src/thp/workflow.rs`): `ThpWorkflow<B: ThpBackend>` drives Handshake → Pairing → Paired lifecycle. State held in `ThpState` with `parking_lot::Mutex`.
- **`PairingController` trait** (`trezor-connect/src/thp/types.rs`): Async trait for custom pairing UX. CLI implements `CliPairingController`.
- **`ThpStorage` trait** (`trezor-connect/src/thp/storage.rs`): `FileStorage` persists host credentials as JSON. Tests use `InMemoryStorage`.
- **`BleProfile`** (`ble-transport`): Pluggable wallet vendor support (currently Trezor Safe 7).

## License

GPL-3.0-only
