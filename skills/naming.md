# Naming

## General Rust Conventions

- Types: `PascalCase` (`BleBackend`, `ThpWorkflow`, `SignTxRequest`)
- Functions/methods: `snake_case` (`create_channel`, `parse_encrypted_response`)
- Constants: `SCREAMING_SNAKE_CASE` (`TREZOR_SERVICE_UUID`, `SLIP44_ETH`)
- Modules: `snake_case` (`backend_impl`, `curve25519`)
- Crate names: `kebab-case` (`thp-crypto`, `ble-transport`, `hw-wallet`)

## Project-Specific Naming

### Crate Prefixes

- `thp-*` — Trezor Host Protocol layer crates
- `hw-*` — Host/wallet-facing crates (CLI, FFI, wallet orchestration)
- `ble-transport` — BLE-specific transport (no prefix, standalone)

### Key Type Names

- `ThpBackend` — protocol backend trait (not `Backend` or `TrezorBackend`)
- `ThpWorkflow` — workflow state machine (not `Session` or `Connection`)
- `BleProfile` — device vendor profile (not `DeviceConfig`)
- `HWCoreError` — FFI error type (not `Error` or `FfiError`)

### Avoid Generic Names

```rust
// bad
struct Config { ... }
fn process(data: &[u8]) { ... }
enum Error { ... }

// good
struct HandshakeOpts { ... }
fn parse_encrypted_response(data: &[u8]) { ... }
enum BackendError { ... }
```

### Boolean Parameters

Prefix with verbs or adjectives that read naturally:

```rust
// bad
fn bootstrap(force: bool, cardano: bool) { ... }

// good
fn bootstrap(force_new_session: bool, derive_cardano: bool) { ... }
```
