# Android Sample App Plan (hw-ffi + hw-wallet)

## Goal
Ship a runnable Android sample app that can:
- Discover Trezor Safe 7 over BLE
- Pair/connect reliably
- Fetch addresses/public keys for ETH/BTC/SOL
- Sign transactions for ETH/BTC/SOL

## Scope
### V1 (in scope)
- Android app shell + Kotlin UI flow
- Rust FFI integration on Android (JNI + native libs packaging)
- BLE scan/connect/session lifecycle
- Pairing (code entry + paired-connection confirmation)
- Address and signing flows for ETH/BTC/SOL
- UX states for loading/prompt/success/error/retry
- Developer docs for local build/run

### Out of scope (later)
- Production app architecture (multi-module/domain layers)
- Background service/daemon behavior
- Play Store release packaging/compliance
- Portfolio/account features

## Current Status (2026-02-18)
Implemented:
- Kotlin bindings generation exists via `just bindings` (`target/bindings/kotlin`).
- Rust FFI surface supports the required wallet workflow primitives.

Missing:
- [ ] No Android project exists under `android/` yet
- [ ] No Android-native Rust build/packaging pipeline for ABIs
- [ ] No Android sample UX for scan/pair/connect/address/sign
- [ ] No Android instrumentation/UI smoke tests

## Milestones
## A1: Android Project Bootstrap
- [ ] Create `android/` Gradle project (Kotlin)
- [ ] Add app module with minimal single-activity UI scaffold
- [ ] Wire generated Kotlin bindings into the app module
- [ ] Add Android permissions and manifest entries for BLE scanning/connection
- [ ] Add root-level run instructions in `android/README.md`

## A2: Native Rust Packaging
- [ ] Add reproducible Android Rust build script for target ABIs
- [ ] Package `libhw_ffi` into `jniLibs` for debug builds
- [ ] Add developer task/command for rebuilding + syncing native libs
- [ ] Verify library loading and basic FFI health check on app startup

## A3: Wallet Workflow Integration
- [ ] Discover and list devices
- [ ] Connect and execute pair-only/connect-ready flows
- [ ] Implement pairing code entry + confirm-connection loop
- [ ] Add chain picker and `getAddress` flow with path/toggles
- [ ] Add chain-specific `signTx` input forms (ETH/BTC/SOL) and result view

## A4: Hardening and UX
- [ ] Surface structured errors with actionable retry hints
- [ ] Add lifecycle-safe session handling across app pause/resume
- [ ] Add deterministic log panel with copy action
- [ ] Add basic input validation for sign/address forms

## A5: Testing + CI
- [ ] Add unit tests for request-building/view-model logic
- [ ] Add instrumentation smoke test for launch + primary controls
- [ ] Add CI check for Android sample build and Kotlin bindings sync

## Immediate Next Tasks
- [ ] Define Android baseline: SDK/NDK versions, minSdk, supported ABIs
- [ ] Create `android/` app skeleton and compile with placeholder screen
- [ ] Add Rust build/sync script for Android ABI artifacts
- [ ] Wire first happy path: scan -> connect -> pair-only -> connect-ready
- [ ] Document local run/debug workflow for contributors
