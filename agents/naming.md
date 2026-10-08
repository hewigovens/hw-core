# Naming

## Rust Conventions

- Types `PascalCase` (`BleBackend`, `ThpWorkflow`), functions and modules `snake_case` (`create_channel`, `thp_backend`), constants `SCREAMING_SNAKE_CASE` (`DEFAULT_ETHEREUM_BIP32_PATH`, `THP_ERROR_DEVICE_LOCKED`), crates `kebab-case` (`thp-proto`, `ble-transport`, `hw-wallet`).

## Project Conventions

- Crate prefixes: `thp-*` for Trezor Host Protocol crates, `hw-*` for host/wallet-facing crates (CLI, FFI, wallet orchestration); `ble-transport` and `trezor-connect` stand alone.
- Established names: `ThpBackend` (protocol backend trait), `ThpWorkflow` (workflow state machine), `BleProfile` (device vendor profile), `HWCoreError` (FFI error type). Do not introduce synonyms.
- Avoid generic names like `Config`, `Error`, `process`; name the concept (`HandshakeOpts`, `BackendError`, `parse_encrypted_response`).
- Boolean parameters read as a claim: `force_new_session`, `derive_cardano`, not `force`, `cardano`.
