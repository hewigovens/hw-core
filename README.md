# hw-core

[![CI](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml/badge.svg)](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hewigovens/hw-core)

Early-stage Rust workspace for host-to-hardware crypto wallets. The first milestone targets the Trezor Host Protocol (THP) with a transport/core stack intended to be shared across multiple vendors. 

- THP reference documentation: [trezor-firmware/docs/common/communication/thp.md](https://github.com/trezor/trezor-firmware/blob/m1nd3r/thp-documentation/docs/common/communication/thp.md).

## What’s implemented

- `trezor-connect`: host workflow layer covering create-channel, Noise handshake, pairing (QR/NFC/code entry), credential issuance, and session creation. Uses the shared THP wire helpers for BLE.
- `thp-proto`: vendored `messages-thp.proto` with prost types + conversions to workflow structs.
- `thp-core`, `thp-codec`, `thp-crypto`: Noise XX session driver, transport framing (CRC/fragmentation), AES/X25519 helpers, and credential discovery logic.
- `ble-transport`: btleplug-powered scaffolding (scan/connect/session) leveraged by the new BLE backend, with channel tests verifying frame encode/decode and state tracking.
- `hw-ffi`: UniFFI-based FFI surface that wraps BLE discovery and THP workflows for mobile/desktop consumers.

## Roadmap

- USB transport: implement a THP link on top of HID/bridge transport and expose via the `usb` feature.
- Persistence: surface pairing credential/tag secrets in a pluggable storage layer for multi-device reuse.
- Multi-vendor abstraction: generalise link/workflow traits so Ledger/Secure Element protocols can share the same host surface.
- Integration tests: flesh out mocked link scenarios (BLE/USB) that exercise protobuf routes end-to-end.

APIs are unstable while we iterate on the transport abstraction and vendor-agnostic workflow surface.

## Workspace layout

- `crates/ble-transport`: btleplug-based BLE manager with pluggable wallet profiles (ready for UniFFI/mobile bindings).
- `crates/thp-codec`: length/CRC framed Thunderbolt Host Protocol packets with property tests.
- `crates/thp-crypto`: Noise XX + CPace helpers shared by higher layers.
- `crates/thp-core`: async session state machine that drives Noise handshakes and encrypted THP requests.
- `crates/thp-proto`: prost-generated THP protobufs and helper adapters.
- `crates/trezor-connect`: host-facing workflow API plus transport backends (BLE today, USB soon™).
- `crates/hw-ffi`: cdylib exposing the BLE manager + THP workflow over UniFFI.

## Feature flags

- `ble`: enables the BLE transport stack (btleplug, Noise handshake, pairing).
- `usb`: placeholder for the upcoming USB/HID transport implementation.

Build everything: `cargo build -p trezor-connect --all-features`. Build BLE-only: `cargo build -p trezor-connect --features ble`.

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
just fmt            # format
just lint           # clippy (workspace)
just test           # cargo test --workspace
just ci             # fmt check + lint + test (mirrors GitHub CI)
just scan-demo      # scan for Trezor devices over BLE (trezor-safe7 feature)
just workflow-demo  # drive the THP BLE workflow (requires a device)
```

## Examples

The BLE transport crate ships with a simple scanner that lists nearby Trezor devices:

```bash
cargo run -p ble-transport \
  --features trezor-safe7,backend-btleplug \
  --example scan_trezor
```

The `trezor-connect` crate includes an end-to-end BLE workflow demo:

```bash
cargo run -p trezor-connect \
  --features ble \
  --example ble_handshake
```

## FFI bindings

The `hw-ffi` crate builds a UniFFI-powered `cdylib` for consumers that need Rust-powered BLE scanning and THP workflows (e.g., mobile apps). Generate language bindings with:

```bash
just bindings  # writes Swift & Kotlin bindings under target/bindings/
```

The helper CLI supports additional languages. For manual invocation or alternate output locations:

```bash
cargo run -p hw-ffi --features bindings-cli --bin generate-bindings \
  --auto target/bindings/swift target/bindings/kotlin
```

Use `--lib <path>` if you want to point at a prebuilt library instead of auto-discovering `target/{debug,release}`.

On Ubuntu runners (including CI) install the Bluetooth dependencies before building the real BLE backend:

```bash
sudo apt-get update
sudo apt-get install -y libdbus-1-dev pkg-config
```
