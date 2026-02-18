# Message Signing Plan

## Goal
Add end-to-end message signing APIs for chains supported by Trezor firmware/protobuf today, wired through:
- `trezor-connect`
- `hw-wallet`
- `hw-ffi`
- `HWCoreKit` + sample app
- `hw-cli`

## Why This Is Simpler Than BTC Transaction Signing
- Message signing is request/response per call (`SignMessage`/`MessageSignature`, `EthereumSignMessage`/`EthereumMessageSignature`).
- No previous-transaction graph, no `TxRequest` multi-step ack loop, and no tx metadata streaming.
- Lower parsing complexity (string/hex payload + path), so implementation risk is mostly input validation and API ergonomics.

## Scope
### V1 (implement now)
- BTC message signing via protobuf `SignMessage -> MessageSignature`
- ETH message signing via protobuf `EthereumSignMessage -> EthereumMessageSignature`
- Chain-aware, typed API surface in Rust/FFI/Swift/CLI
- Sample app UI for BTC/ETH message signing

### Deferred
- SOL message signing (no current Trezor Connect/protobuf API surface found in Suite for Solana sign-message)
- Message verification APIs (`VerifyMessage`, `EthereumVerifyMessage`) unless needed immediately
- EIP-712 typed-data signing (`EthereumSignTypedHash`)

## Implementation Work Items
1. `trezor-connect`: protocol + backend
- Add message request/response domain types in `/Users/hewig/workspace/hw-core/crates/trezor-connect/src/thp/types.rs`.
- Add protobuf encode/decode in `/Users/hewig/workspace/hw-core/crates/trezor-connect/src/thp/proto.rs` for:
  - BTC `SignMessage` / `MessageSignature`
  - ETH `EthereumSignMessage` / `EthereumMessageSignature`
- Add backend methods and BLE implementation in `/Users/hewig/workspace/hw-core/crates/trezor-connect/src/ble.rs` with button/failure handling consistent with address/sign-tx flows.

2. `hw-wallet`: request building + normalization
- Add chain-specific message request builders/parsers in `/Users/hewig/workspace/hw-core/crates/hw-wallet/src`.
- Support UTF-8 vs hex input mode (explicit flag), validate path per chain, and normalize output signature format.

3. `hw-ffi`: exported typed API
- Add UniFFI records/enums for message signing request/result in `/Users/hewig/workspace/hw-core/crates/hw-ffi/src/types.rs`.
- Add session API in `/Users/hewig/workspace/hw-core/crates/hw-ffi/src/ble.rs`.
- Keep naming chain-agnostic (no legacy `HW`/`Ffi` prefixes).

4. Apple wrapper + sample app
- Add Swift wrappers in `/Users/hewig/workspace/hw-core/apple/HWCoreKit/Sources/HWCoreKit`.
- Add message-sign UI sections in sample app view model/views under `/Users/hewig/workspace/hw-core/apple/HWCoreKitSampleApp/Sources/HWCoreKitSampleApp`.
- Log payload preview + signature result in copyable format.

5. CLI surface
- Add `sign-message btc` and `sign-message eth` commands in `/Users/hewig/workspace/hw-core/crates/hw-cli/src/commands`.
- Align JSON/flags with wallet builder semantics (`--message`, `--hex`, `--path`, chain options).

## Tests
1. Protocol tests
- Protobuf encode/decode unit tests for BTC/ETH message sign requests and responses.

2. Backend/workflow tests
- Mock backend tests to verify correct method dispatch, failure mapping, and response mapping.

3. Wallet/FFI tests
- Input validation tests (bad path, empty message, malformed hex).
- Mapping tests from FFI request to backend request and back.

4. App/CLI smoke tests
- CLI happy-path command invocation tests.
- Sample app UI smoke path: connect -> sign message -> signature shown in logs.

## Acceptance Criteria
- `hw-cli` can sign BTC and ETH messages end-to-end on paired device.
- `HWCoreKitSampleApp` can sign BTC and ETH messages end-to-end.
- Errors are categorized and surfaced through existing `HwCoreError` mapping.
- No regressions in existing address/sign-tx flows.
