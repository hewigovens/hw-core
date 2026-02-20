# Message Signing Plan

## Goal
Keep message signing as one coherent surface across stack layers while matching Trezor Suite behavior:
- BTC message signing (`SignMessage`)
- ETH EIP-191 message signing (`EthereumSignMessage`)
- ETH EIP-712 structured-data signing (`EthereumSignTypedData`)

## Current State
Implemented across:
- `trezor-connect`
- `hw-wallet`
- `hw-ffi`
- `HWCoreKit` + sample app
- `hw-cli`

Suite-aligned ETH behavior:
- EIP-191 and EIP-712 are both supported.
- For TS7/core devices, EIP-712 uses full structured-data flow:
  - `EthereumSignTypedData`
  - `EthereumTypedDataStructRequest`/`Ack`
  - `EthereumTypedDataValueRequest`/`Ack`
  - `EthereumTypedDataSignature`
- Hash-based EIP-712 (`EthereumSignTypedHash`) remains available as a compatibility path.

CLI surface (simplified):
- `sign-message btc ...`
- `sign-message eth --type eip191 ...` (default type)
- `sign-message eth --type eip712 --data-file <path>`

Interactive CLI session mode has been removed to reduce maintenance; interactive signing UX lives in macOS/iOS app surfaces.

## Simplification Review
### Done
- Unified EIP-712 into `sign-message` instead of separate `sign-typed-data` command.
- Added fast-fail ETH request validation/build before BLE connect in CLI command path.
- Reused one signature-print helper for consistent output formatting.
- Removed REPL-style interactive CLI mode and `pair --interactive` flow.
- Extracted EIP-712 type/value adapter logic into a dedicated module with Suite-parity tests.
- Extracted shared CLI BLE scan/connect/workflow bootstrap into `commands/common.rs` and reused it in `address`, `sign`, `sign-message`, and `pair`.

### Next Simplifications (recommended)
1. Centralize `sign-message` mode validation
- Problem: argument compatibility rules and typed-data file loading are coupled to the command runner function.
- Plan: add one parser/validator module returning typed request enums, so request construction and validation tests stay isolated from transport setup.

2. Add fixture coverage for invalid ETH mode combinations
- Examples:
  - `--type eip712` with `--message`
  - `--type eip191` with `--data-file`
  - missing `--data-file` for eip712
  - malformed EIP-712 JSON / unknown struct/type references

## Scope
### In Scope
- BTC + ETH message signing.
- ETH EIP-712 structured-data signing for TS7.
- Rust/FFI/Swift/CLI parity.

### Deferred
- Solana message signing.
- Message verification APIs.
- Full UI-level EIP-712 data authoring UX in sample app (currently API accepts raw JSON input).

## Acceptance Criteria
- `hw-cli` signs:
  - BTC message
  - ETH EIP-191 message
  - ETH EIP-712 typed data from JSON (`--data-file <path>`)
- `HWCoreKitSampleApp` signs BTC/ETH messages end-to-end.
- `hw-ffi` exposes typed-data signing with consistent normalized output.
- No regressions in address/sign-tx workflows.
