# thp-rs (WIP)

Early-stage Rust workspace implementing the Trezor Host Protocol (THP). Reference specification lives in the [official THP documentation](https://github.com/trezor/trezor-firmware/blob/m1nd3r/thp-documentation/docs/common/communication/thp.md).

## Workspace Layout

- `crates/thp-codec`: Transport framing (length prefix, CRC, chunking) with property tests.
- `crates/thp-crypto`: Noise XX cipher helpers (X25519 + AES-GCM) used by both the codec and higher layers.
- `crates/thp-core`: Asynchronous session state machine that drives Noise handshakes and encrypted request/response over an abstract `Link`.
- `crates/trezor-connect`: Host-facing workflow layer that mirrors the TypeScript `trezor-connect` code. It now owns the ported THP cryptography primitives (Noise handshake derivations, credential discovery, QR/NFC/code-entry tag validators) and will grow the transport backends.

Bring your own Link implementation (BLE/USB). APIs are unstable while we wire UniFFI bindings and integrate device transports.

## Feature Flags

- `trezor-connect` exposes opt-in channel features:
  - `usb`: gate code that depends on a USB THP backend implementation (stub today).
  - `ble`: gate code that depends on a BLE THP backend implementation (stub today).

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
