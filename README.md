# thp-rs (WIP)

Early-stage Rust workspace implementing the Trezor Host Protocol (THP). The in-flight design is tracked in [`doc/`](doc) with the canonical protocol reference in the [THP documentation](https://github.com/trezor/trezor-firmware/blob/m1nd3r/thp-documentation/docs/common/communication/thp.md).

## Implementation status

- `trezor-connect` workflow layer exposes pairing + channel set-up flows backed by the ported Noise/CPace helpers and protobuf conversions.
- `thp-proto` venders the upstream `messages-thp.proto` definitions and derives prost structs for the rest of the workspace.
- `thp-core`, `thp-codec`, and `thp-crypto` cover the core state machine, transport framing, and Noise crypto used by the workflows.
- `ble-transport` hosts btleplug-driven scaffolding for scanning and session management, ready to be wired to real THP traffic.

Still missing:

- Real BLE/USB transport backends that speak the protobuf messages (current `NotImplemented` stubs in `trezor-connect`).
- Persisting/validating pairing tag secrets returned by devices during authentication.
- End-to-end tests across the protobuf conversions and transport boundaries once the backends land.

APIs are unstable while we integrate UniFFI bindings and device transports.

## Workspace layout

- `crates/ble-transport`: btleplug-based BLE management (scan/connect/session) with pluggable wallet profiles.
- `crates/thp-codec`: transport framing (length prefix, CRC, chunking) with property tests.
- `crates/thp-crypto`: Noise XX cipher helpers (X25519 + AES-GCM) reused by codec and higher layers.
- `crates/thp-core`: async session state machine that drives Noise handshakes and encrypted request/response over an abstract `Link`.
- `crates/thp-proto`: generated THP protobuf messages plus helper traits.
- `crates/trezor-connect`: host-facing workflow API, protobuf conversions, and (future) transport backends.

## Feature flags

- `trezor-connect` exposes opt-in channel features:
  - `usb`: gate code that depends on a USB THP backend (stub today).
  - `ble`: gate code that depends on a BLE THP backend (stub today).

Build everything: `cargo build -p trezor-connect --all-features`. Pick a channel: `cargo build -p trezor-connect --features ble`.

## Dev quickstart

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace
```

Or use the `just` helpers described below.

## Tooling

Install [just](https://github.com/casey/just) and run:

```bash
just fmt     # format
just lint    # clippy (workspace)
just test    # cargo test --workspace
just ci      # fmt check + lint + test (mirrors GitHub CI)
```

Contributions and specs welcome!
