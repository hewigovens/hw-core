# thp-rs (WIP)

Early-stage Rust workspace implementing the Trezor Host Protocol (THP). Reference specification lives in the [official THP documentation](https://github.com/trezor/trezor-firmware/blob/m1nd3r/thp-documentation/docs/common/communication/thp.md).

## Status

- `thp-codec`: Frame chunking + CRC verification with property tests.
- `thp-crypto`: Noise XX cipher suite helpers (X25519 + AES-GCM).
- `thp-core`: Async handshake + encrypted request pipeline with mock `Link`.
- `trezor-connect`: WIP high-level THP workflow orchestration (channel + pairing glue) mirroring the TypeScript `trezor-connect` implementation, plus freshly ported THP crypto helpers (Noise handshake, credential lookup, QR/NFC/code-entry validators).

Bring your own Link implementation (BLE/USB). APIs are unstable while we wire UniFFI bindings and integrate device transports.

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
