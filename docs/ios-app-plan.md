# iOS App Plan (hw-ffi + hw-wallet)

## Goal
Ship a production-ready iOS app that can:
- Discover Trezor Safe 7 over BLE
- Pair/connect reliably
- Fetch Ethereum address/public key
- Sign Ethereum transactions

## Scope
### V1 (in scope)
- BLE scan/connect/session lifecycle
- THP channel + handshake + paired-connection confirmation
- Pairing (code entry)
- ETH address and ETH sign flows
- Persistent host state on iOS (same behavior as CLI)
- Basic UX states (loading, prompt, success, error, retry)

### Out of scope (later)
- BTC flows
- NFC/QR pairing methods
- Background sync/daemon behavior
- Portfolio/account features

## Target Architecture
1. Rust core:
   - `hw-wallet`: workflow orchestration, chain/path/sign helpers
   - `trezor-connect`: THP protocol + BLE backend
2. FFI boundary:
   - `hw-ffi` exposes stable async API via UniFFI
3. iOS app (Swift):
   - `HWCoreKit` wrapper around generated UniFFI Swift bindings
   - Feature modules: `Pairing`, `Address`, `Signing`
   - UI state machine driven by FFI events/results

## Current FFI Status
Implemented:
- Scan/connect
- Create channel
- Handshake
- Create session
- State/config inspection

Missing for iOS V1:
- Pairing interaction API (code-entry prompt/submit)
- Address API
- Sign API
- File-backed host-state storage control
- Retry policy controls and richer error taxonomy for UI

## Milestones
## M1: Expand Rust FFI Surface
- [x] Add `pairing_start/pairing_submit_code/pairing_confirm_connection` methods
- [x] Add `get_address` method (+ options: show on device, include public key, chunkify)
- [x] Add `sign_eth_tx` method (typed input model, no raw JSON in Swift)
- [x] Add storage configuration in FFI (`storage_path` or `app_group`-safe path)
- [x] Add structured FFI errors (`Ble`, `Workflow`, `Device`, `Validation`, `Timeout`)
- [x] Add FFI integration tests for end-to-end state transitions

## M2: iOS Core Integration
- [x] Add generated Swift bindings to iOS workspace
- [x] Build `HWCoreKit` thin wrapper with async Swift API
- [x] Add cancellation and timeout wrappers around long-running calls
- [x] Map Rust errors to user-facing Swift domain errors
- [x] Add deterministic logging hooks (redacted)

## M3: Pairing + Session UX
- [ ] Device list and connect screen
- [ ] Pairing code-entry UI loop
- [ ] Connection-confirmation path for already-paired devices
- [ ] Session-ready state and reconnect flow
- [ ] Retry UX for transient busy/not-ready firmware states

## M4: Address + Sign UX
- [ ] ETH address screen (default path + editable path)
- [ ] Optional show-on-device and public key toggles
- [ ] ETH sign screen (typed fields, validation, preview)
- [ ] Result screen (signature components + copy/export)

## M5: Hardening + Release Readiness
- [ ] Persisted host state migration/versioning
- [ ] Crash-safe recovery after BLE disconnect
- [ ] Telemetry/error metrics (privacy-safe)
- [ ] End-to-end manual test matrix (locked/unlocked, paired/unpaired, stale pairing)
- [ ] TestFlight release checklist

## API Contract Proposal (Swift-facing)
- `discoverTrezor(timeoutMs) async throws -> [Device]`
- `connect(deviceId) async throws -> Session`
- `session.prepareChannelAndHandshake(tryUnlock: Bool) async throws -> HandshakeState`
- `session.startPairing() async throws -> PairingPrompt`
- `session.submitPairingCode(_ code: String) async throws -> PairingProgress`
- `session.confirmPairedConnection() async throws`
- `session.createWalletSession(...) async throws`
- `session.getEthereumAddress(...) async throws -> AddressResult`
- `session.signEthereumTx(...) async throws -> SignResult`
- `session.disconnect() async`

### Async UX Pattern (SwiftUI/macOS)
- Expose an `AsyncStream<WalletEvent>` from `HWCoreKit` so UI can react to:
  - pairing prompts
  - button-request/device-confirm states
  - progress transitions
  - recoverable errors/retry hints
- Keep FFI calls request/response async; keep prompts/progress as event stream.
- Avoid CLI-style blocking interaction loops in Swift; model flows as async state transitions.

## Risks and Mitigations
- BLE instability / transient firmware busy:
  - Keep retry with bounded backoff at FFI layer
- Pairing state drift between host/device:
  - Add “reset local credentials” and clear-storage UX path
- App lifecycle interruptions:
  - Persist workflow-relevant state and reconnect gracefully

## Task Tracking
### Immediate next tasks
- [x] Implement M1 FFI methods for pairing/address/sign
- [x] Add FFI test for “paired handshake requires connection confirmation”
- [x] Add iOS wrapper package scaffold (`HWCoreKit`)
- [x] Add sample app scaffold using `HWCoreKit` API
- [ ] Wire first happy path: scan -> pair -> address
