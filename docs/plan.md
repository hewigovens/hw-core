# hw-core Execution Plan

Last updated: 2026-02-20
Status legend: TODO | IN_PROGRESS | DONE | BLOCKED

## Objective
Consolidate current implementation into a release-ready baseline across CLI, FFI, and app surfaces, with protocol parity and validation confidence.

## Workstream A: Bitcoin Signing Completion
Owner: Protocol/Core
Status: IN_PROGRESS

### Scope
- Finish advanced BTC `TxRequest` handling in `trezor-connect`.
- Keep request/response behavior aligned with Trezor Suite.

### Completed
- `ref_txs` request model, validation, and prev-tx payload support.
- Implemented handling for `TXMETA`, `TXINPUT`, `TXOUTPUT`, `TXEXTRADATA`.
- Added proto/wallet/backend tests for prev-tx and bounds validation.

### Remaining
- [ ] Implement `TXORIGINPUT` handling.
- [ ] Implement `TXORIGOUTPUT` handling.
- [ ] Implement `TXPAYMENTREQ` handling.
- [ ] Add integration tests for mixed `TX*` request sequences.

### Exit Criteria
- BTC signing no longer fails on advanced firmware request variants.

## Workstream B: Message Signing Hardening
Owner: Wallet/CLI/FFI
Status: IN_PROGRESS

### Scope
- Keep one coherent message-signing surface for BTC + ETH.
- Maintain Suite-aligned ETH behavior (EIP-191 and EIP-712 typed data flow).

### Completed
- End-to-end BTC and ETH message signing across `trezor-connect`, `hw-wallet`, `hw-ffi`, `HWCoreKit`, and `hw-cli`.
- Unified CLI command surface under `sign-message`.

### Remaining
- [ ] Extract CLI sign-message argument validation into a dedicated parser/validator module.
- [ ] Add negative fixture coverage for invalid ETH mode combinations and malformed EIP-712 payloads.
- [ ] Confirm no regressions in address/sign-tx flows after validator refactor.

### Exit Criteria
- Clear, testable, and transport-independent message-signing request validation.

## Workstream C: Apple App Hardening
Owner: Apple/FFI
Status: IN_PROGRESS

### Scope
- Preserve reliable scan/pair/connect/address/sign behavior on iOS/macOS.
- Keep lifecycle and reconnect behavior deterministic.

### Completed
- `HWCoreKit` wrapper and sample UI workflow integration.
- iOS and macOS UI smoke targets (`just test-ios-ui`, `just test-mac-ui`).
- Lifecycle recovery hooks for background/foreground BLE interruptions.

### Remaining
- [ ] Keep smoke scenarios embedded in app/UI tests and contributor docs.
- [ ] Add focused regression cases for stale pairing credentials and reconnect recovery.

### Exit Criteria
- Reproducible Apple-side behavior for paired/unpaired and lifecycle-interruption paths.

## Workstream D: Android Sample App
Owner: Android/FFI
Status: TODO

### Scope
- Create a runnable Android sample app using generated Kotlin bindings.

### Tasks
- [ ] Bootstrap `android/` Gradle project and app module.
- [ ] Implement Rust native library packaging for target ABIs.
- [ ] Add BLE permissions and scan/connect/pair flows.
- [ ] Add address and sign flows for ETH/BTC/SOL.
- [ ] Add instrumentation smoke test for app launch and core controls.
- [ ] Write `android/README.md` run/build instructions.

### Exit Criteria
- A contributor can run Android sample happy path locally from repo docs.

## Workstream E: Validation and CI
Owner: DevEx
Status: IN_PROGRESS

### Scope
- Increase confidence in real-device and UI workflows.
- Align CI coverage with supported developer surfaces.

### Tasks
- [ ] Add CI checks for Apple sample build + UI smoke jobs (where runner availability allows).
- [ ] Add CI checks for Android sample build once project lands.
- [ ] Keep smoke command references current in `README.md` and `CONTRIBUTING.md`.
- [ ] Keep this file and `docs/roadmap.md` as the only active planning docs.

### Exit Criteria
- CI and docs reflect what is actually supported and validated.

## Workstream F: Code Refactoring and Simplification
Owner: Core
Status: IN_PROGRESS

### Scope
- Reduce complexity and duplication across CLI, wallet, FFI, and protocol layers.
- Improve readability, testability, and maintainability without changing external behavior.

### Tasks
- [ ] Identify and remove duplicated request-building and validation logic across surfaces.
- [ ] Break large modules/functions into smaller, focused units with clearer boundaries.
- [ ] Normalize error mapping and naming conventions at crate boundaries.
- [ ] Add focused regression tests around refactored paths before and after changes.
- [ ] Document key architecture decisions and ownership boundaries in code comments/docs.

### Exit Criteria
- Lower maintenance cost, clearer module ownership, and no behavior regressions in existing flows.

## Validation Checklist (Consolidated)
- [ ] `just cli-scan` discovers expected device(s).
- [ ] `just cli-pair` succeeds on first pairing and reuse path.
- [ ] `just cli-address-eth` and `just cli-sign-eth` succeed on paired device.
- [ ] BTC signing validates both supported and unsupported advanced request paths clearly.
- [ ] `just test-ios-ui` and `just test-mac-ui` pass.
- [ ] Android sample launch/build smoke passes once app exists.

## Risks and Dependencies
- Advanced BTC firmware request coverage remains the biggest protocol gap.
- BLE reliability is sensitive to platform adapter behavior and timeout policy.
- Android sample progress depends on reliable native packaging + device BLE permissions handling.
- Trezor Suite behavior remains source of truth for request shapes and UX parity.
