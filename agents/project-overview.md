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

## Behavior Ownership

- `ble-transport` owns BLE discovery, connection, and byte I/O; keep wallet orchestration out of the transport layer.
- `trezor-connect` owns Trezor protocol requests, THP state transitions, and the protocol backend.
- `hw-wallet` owns shared wallet session orchestration and retry policy used by CLI and FFI consumers; put shared flow fixes here rather than duplicating them in adapters.
- `hw-chain` owns chain metadata and default derivation paths; `thp-proto` owns generated wire types, not workflow policy.
- `hw-cli` and `hw-ffi` adapt inputs, outputs, and lifecycle to their consumers. Keep shared protocol and wallet policy in the owning Rust layer; platform apps own presentation and platform interaction.

For cross-layer bugs, trace input → adapter → wallet orchestration → protocol/transport → response or error → presented state. Fix the lowest shared layer that owns the contract, then verify affected CLI, FFI, Swift, or Kotlin boundaries for their independent risks.

Async results must still belong to the active connection/session when applied. Check cancellation, reconnect, and replacement state before accepting a delayed completion; preserve valid state unless the contract requires invalidation.

## Feature Flags

- `ble` on `trezor-connect`: enables BLE transport (btleplug, Noise handshake, pairing)
- `test-support` on `trezor-connect`: exposes the shared `thp::testing::MockBackend` for dev-dependencies

## Key Design Patterns

- **`ThpBackend` trait** (`trezor-connect/src/thp/backend.rs`): Async trait defining all THP protocol operations. `BleBackend` is the concrete implementation. Tests use `MockBackend`.
- **Workflow state machine** (`trezor-connect/src/thp/workflow.rs`): `ThpWorkflow<B: ThpBackend>` drives Handshake → Pairing → Paired lifecycle. State held in a `ThpState` field on the workflow.
- **`PairingController` trait** (`trezor-connect/src/thp/types.rs`): Async trait for custom pairing UX. CLI implements `CliPairingController`.
- **`ThpStorage` trait** (`trezor-connect/src/thp/storage/mod.rs`): `FileStorage` persists host credentials as JSON. Tests use `InMemoryStorage`.
- **`BleProfile`** (`ble-transport`): Pluggable wallet vendor support (currently Trezor Safe 7).

## License

Apache-2.0
