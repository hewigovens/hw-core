# Roadmap

## Implemented

- BLE discovery, connection, and THP session management (scan/connect/pairing/credential persistence)
- Noise XX handshake and encrypted communication over BLE
- THP host workflow: create-channel, handshake, pairing (QR/NFC/code entry), session creation
- Vendored THP protobuf types with prost
- Pluggable BLE wallet profiles (Trezor Safe 7)
- Interactive CLI: `scan`, `pair`, `address eth`
- Shared wallet orchestration layer (`hw-wallet`) for CLI and FFI
- UniFFI-based FFI surface with Swift/Kotlin binding generation

## Current: CLI Wallet v1 (Trezor Safe 7 over BLE)

Deliver an interactive CLI that can pair, read ETH addresses, and sign ETH transactions with a real Trezor Safe 7 over BLE.

| Phase | Description | Status |
|-------|-------------|--------|
| P0 | Protocol contract and design | Mostly done (ETH wire contract still blocked) |
| P1 | CLI skeleton (`hw-cli`, `hw-wallet`) | Done |
| P2 | Pairing UX and persistence | Done |
| P3 | Ethereum address flow | Done (tests in progress) |
| P4 | Ethereum signing flow | TODO |
| P5 | Reliability, validation, docs | TODO |

See [cli-wallet-v1.md](cli-wallet-v1.md) for the full task tracker.

## Future

- **USB transport**: THP link on top of HID/bridge transport, exposed via the `usb` feature flag.
- **Multi-vendor abstraction**: generalise link/workflow traits so Ledger/Secure Element protocols can share the same host surface.
- **Integration tests**: mocked link scenarios (BLE/USB) exercising protobuf routes end-to-end.

APIs are unstable while we iterate on the transport abstraction and vendor-agnostic workflow surface.
