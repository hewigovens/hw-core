# hw-core Execution Plan

Last updated: 2026-02-23
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
Status: IN_PROGRESS

### Scope
- Create a runnable Android sample app using generated Kotlin bindings.

### Completed
- Bootstrapped `android/` Gradle project with `lib` and `sample-app` modules.
- Rust native library packaging via `cargo-ndk` for arm64-v8a, armeabi-v7a, x86_64.
- BLE permissions (runtime + manifest) and scan/connect/pair UI flows.
- Android JNI bootstrap for btleplug (`btleplug::platform::init`) to avoid Droidplug init failures during scan.
- ETH/BTC/SOL address and sample sign-transaction flows in sample app.
- ETH/BTC message signing flow in sample app.
- `android/README.md` with build/run instructions.
- Unified `scripts/sync-bindings.sh` supporting `--android` and `--apple` flags.
- Added `just run-android`, `just android-devices`, and `just android-logs` for consistent build/install/log flow.
- Added Android sample lifecycle persistence for UI state and logs across activity recreation.
- Added Android sample UI tab layout (`Main` / `Config` / `Logs`) and improved controls placement.
- Added Android-side THP create-channel diagnostics (`hwcore create_channel: ...`) and workflow progress events (`CREATE_CHANNEL_ERROR`).
- Resolved Android THP create-channel stall by fixing Droidplug queueing around subscribed notification reads.
- Added explicit Android disconnect hard-close fallback and BLE manager reset on sample-app disconnect/reset for reliable teardown.

### Latest Status (2026-02-22)
- Real-device Android pair/connect/session-ready now succeeds after Droidplug notification/read queue fixes.
- Address retrieval now succeeds on Android (`GET_ADDRESS_OK` observed on real device).
- Disconnect path now invokes BLE teardown reliably from sample app (`disconnect` callback path confirmed).

### Remaining
- [ ] Add/verify real-device regression coverage for pair/connect/address/sign/disconnect across repeated runs.
- [ ] Finalize Android reconnect policy and lifecycle UX parity with iOS sample.
- [ ] Add instrumentation smoke test for app launch and core controls.

### Exit Criteria
- A contributor can run Android sample happy path locally from repo docs, including stable pair/connect/address/sign/disconnect on real device.

## Workstream E: Validation and CI
Owner: DevEx
Status: IN_PROGRESS

### Scope
- Increase confidence in real-device and UI workflows.
- Align CI coverage with supported developer surfaces.

### Tasks
- [ ] Add CI checks for Apple sample build + UI smoke jobs (where runner availability allows).
- [x] Add CI checks for Android sample build (`android-ci.yml`).
- [ ] Keep smoke command references current in `README.md` and `CONTRIBUTING.md`.
- [x] Keep this file and `docs/roadmap.md` as the only active planning docs.

### Exit Criteria
- CI and docs reflect what is actually supported and validated.

## Workstream F: Code Refactoring and Simplification
Owner: Core
Status: IN_PROGRESS

### Scope
- Reduce complexity and duplication across CLI, wallet, FFI, and protocol layers.
- Improve readability, testability, and maintainability without changing external behavior.

### Completed
- Merged `thp-codec` into `thp-crypto` (workspace reduced from 10 to 9 crates).
- Refactored `AGENTS.md` into modular `skills/` directory with topic-specific docs.
- Moved BLE scan/connect orchestration from `backend_impl.rs` into `ble.rs`, simplifying backend implementation.
- Removed dead code and unused error variants across `hw-ffi`, `hw-wallet`, `thp-core`.
- Fixed `decode_failure_reason` to return structured `BackendError` variants for known firmware error codes, preserving retry-loop classification of `DeviceBusy`/`DeviceFirmwareBusy`.
- Cleaned up clippy warnings and tightened error handling in crypto and transport layers.

### Remaining
- [ ] Identify and remove duplicated request-building and validation logic across surfaces.
- [ ] Break large modules/functions into smaller, focused units with clearer boundaries.
- [ ] Normalize error mapping and naming conventions at crate boundaries.
- [ ] Add focused regression tests around refactored paths before and after changes.

### Exit Criteria
- Lower maintenance cost, clearer module ownership, and no behavior regressions in existing flows.

## Workstream G: Library Distribution
Owner: DevEx/Release
Status: TODO

### Scope
- Make hw-core consumable by third-party Android and iOS/macOS apps.

### Tasks
- [ ] Android: add Gradle `maven-publish` config to `android/lib` for AAR publishing.
- [ ] Android: CI release job that runs `just build-android-release` and publishes AAR to Maven Central.
- [ ] iOS/macOS: build `libhwcore.a` for all platform slices (iOS device, iOS simulator, macOS).
- [ ] iOS/macOS: produce `HWCore.xcframework` via `xcodebuild -create-xcframework`.
- [ ] iOS/macOS: host XCFramework as a binary target in `HWCoreKit/Package.swift` for SPM consumption.
- [ ] Tag-based CI release pipeline producing versioned AAR + XCFramework artifacts.
- [ ] Document integration steps for third-party consumers (Android + iOS).

### Exit Criteria
- A third-party app can depend on hw-core via Maven Central (Android) or SPM binary target (iOS/macOS).

## Validation Checklist (Consolidated)
- [ ] `just cli-scan` discovers expected device(s).
- [ ] `just cli-pair` succeeds on first pairing and reuse path.
- [ ] `just cli-address-eth` and `just cli-sign-eth` succeed on paired device.
- [ ] BTC signing validates both supported and unsupported advanced request paths clearly.
- [ ] `just test-ios-ui` and `just test-mac-ui` pass.
- [x] Android sample launch/build smoke passes (`just build-android`, Gradle assembleDebug).
- [x] Android sample real-device `connect-ready` reaches `SESSION_READY` without timing out at `CREATE_CHANNEL`.

## Risks and Dependencies
- Advanced BTC firmware request coverage remains the biggest protocol gap.
- BLE reliability is sensitive to platform adapter behavior and timeout policy.
- Android sample progress depends on reliable native packaging + device BLE permissions handling.
- Android BLE transport may diverge from iOS/macOS behavior (GATT write/notify semantics, chunk sizing, callback timing), causing THP channel bootstrap stalls.
- Trezor Suite behavior remains source of truth for request shapes and UX parity.
