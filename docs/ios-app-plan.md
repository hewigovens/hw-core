# iOS/macOS App Plan (hw-ffi + hw-wallet)

## Goal
Ship a production-ready mobile/desktop app that can:
- Discover Trezor Safe 7 over BLE
- Pair/connect reliably
- Fetch addresses/public keys for ETH/BTC/SOL
- Sign transactions for ETH/BTC/SOL

## Scope
### V1 (in scope)
- BLE scan/connect/session lifecycle
- THP channel + handshake + paired-connection confirmation
- Pairing (code entry)
- Address and signing flows for ETH/BTC/SOL
- Persistent host state (same behavior as CLI)
- UX states for loading/prompt/success/error/retry

### Out of scope (later)
- NFC/QR pairing methods
- Background sync/daemon behavior
- Portfolio/account features

## Current Status (2026-02-18)
Implemented:
- Rust + FFI workflow surface:
  - `pairing_start`, `pairing_submit_code`, `pairing_confirm_connection`
  - `get_address` with `path/show_on_device/include_public_key/chunkify`
  - `sign_tx` for ETH/BTC/SOL through typed `SignTxRequest`
  - file-backed storage path control
  - structured `HwCoreError` categories mapped to Swift
- `HWCoreKit` async wrapper with timeout/cancellation and event stream support
- Sample app stateful workflow UI:
  - scan, pair-only, connect-ready, disconnect
  - pairing alert loop
  - chain picker (ETH/BTC/SOL)
  - editable address path + toggles
  - typed sign inputs by chain + preview
  - signature/address/log copy actions (+ signature export)

Known limitation:
- Advanced BTC signing request types (`TxExtraData`, `TxOrigInput`, `TxOrigOutput`, `TxPaymentReq`, and prev-tx lookup by `tx_hash`) are intentionally not implemented in `trezor-connect` yet. Wallet layer must preload/provide required tx context before calling signing APIs.

Still missing (repo audit):
- [ ] Implement advanced BTC `TxRequest` handling in `trezor-connect` for prev-tx and extra-data request types
- [ ] Add message-signing flows (ETH/BTC/SOL where firmware supports) across `trezor-connect` -> `hw-wallet` -> `hw-ffi` -> `HWCoreKit` + sample app UI (plan: `docs/message-sign-plan.md`)

## Milestones
## M1: Expand Rust FFI Surface
- [x] Pairing interaction APIs (start/submit/confirm)
- [x] Address API with options
- [x] Typed signing API (chain-agnostic `SignTxRequest`)
- [x] Storage configuration support
- [x] Structured FFI errors
- [x] Integration tests for end-to-end state transitions

## M2: Apple Core Integration
- [x] Generated Swift bindings integrated
- [x] `HWCoreKit` thin wrapper with async API
- [x] Timeout/cancellation wrappers
- [x] Rust-to-Swift error mapping
- [x] Deterministic logging hooks

## M3: Pairing + Session UX
- [x] Device list and connect screen
- [x] Pairing code-entry UI loop
- [x] Connection-confirmation path for already-paired devices
- [x] Session-ready state and reconnect flow
- [x] Retry behavior for transient busy/not-ready states in workflow path

## M4: Address + Sign UX
- [x] Address screen with default + editable path
- [x] Show-on-device and include-public-key toggles
- [x] Chain-specific sign forms (ETH/BTC/SOL) with validation and preview
- [x] Result actions (copy/export) in sample app

## M5: Hardening + Release Readiness
- [x] Real iOS app target (`apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj` with local `HWCoreKit` dependency)
- [x] macOS UI launch/control smoke test target (`just test-mac-ui`)
- [x] Persisted host state migration/versioning strategy (`HostSnapshot.schema_version`, legacy v0 migration, and forward-version guard in `FileStorage`)
- [x] Crash-safe recovery after BLE disconnect/app lifecycle interruption (sample app background disconnect + foreground recovery path)
- [x] End-to-end manual matrix (locked/unlocked, paired/unpaired, stale pairing) in `docs/ios-manual-matrix.md`

## API Contract (Swift-facing)
- `discoverTrezor(timeoutMs) async throws -> [Device]`
- `connect(device) async throws -> WalletSession`
- `session.sessionState() async throws -> SessionState`
- `session.pairOnly(tryToUnlock) async throws -> SessionState`
- `session.connectReady(tryToUnlock) async throws -> SessionState`
- `session.startPairing() async throws -> PairingPrompt`
- `session.submitPairingCode(_ code) async throws -> PairingProgress`
- `session.confirmPairedConnection() async throws -> PairingProgress`
- `session.createWalletSession(...) async throws`
- `session.getAddress(...) async throws -> AddressResult`
- `session.signTx(...) async throws -> SignTxResult`
- `session.disconnect() async`

## Immediate Next Tasks
- [ ] Implement advanced BTC `TxRequest` handling in `trezor-connect` for prev-tx and extra-data request types
- [ ] Add message-signing API surface and UI paths (CLI + FFI + Swift wrapper) per `docs/message-sign-plan.md`
- [x] Expose workflow-level reconnect/backoff policy controls via FFI + `HWCoreConfig`
- [x] Add iOS UI smoke tests for scan/pair/connect/address/sign flows (`just test-ios-ui`)
- [x] Write iOS manual validation matrix (`docs/ios-manual-matrix.md`)
