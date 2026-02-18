# Roadmap

Last updated: 2026-02-18

## Implemented

- BLE discovery, connection, THP session lifecycle, pairing, and credential persistence.
- Noise XX handshake and encrypted BLE THP messaging.
- THP host workflow: create-channel, handshake, pairing, session creation.
- Vendored THP protobuf types and host encode/decode mappings.
- Shared orchestration layer (`hw-wallet`) used by CLI and FFI.
- CLI flows for scan/pair/address/sign with ETH/BTC/SOL transaction signing paths.
- UniFFI-based `hw-ffi` surface with Swift and Kotlin binding generation.
- Apple integration:
  - `HWCoreKit` Swift wrapper package.
  - macOS + iOS sample app (`HWCoreKitSampleApp`).
  - macOS UI smoke test target (`just test-mac-ui`).
- Mock-backed tests for workflow/session/address/sign orchestration.

## Open Gaps (Short Term)

- Advanced Bitcoin signing request handling is incomplete (`TxExtraData`, `TxOrigInput`, `TxOrigOutput`, `TxPaymentReq`, prev-tx requests by `tx_hash`).
- Host snapshot schema migration/versioning is not defined yet.
- App lifecycle crash/recovery behavior is not hardened for interrupted BLE sessions.
- Privacy-safe telemetry/error metrics are not implemented.
- iOS UI smoke tests (scan/pair/connect/address/sign) are not implemented yet.
- Android sample app is not started (only Kotlin bindings generation exists).

## Next Actions (can be in Parallel)

| Workstream | Scope | Owner (agent) | Exit Criteria |
|---|---|---|---|
| A. BTC protocol completion | Implement advanced BTC `TxRequest` handling in `trezor-connect` + tests using realistic prev-tx fixtures | Protocol agent | BTC signing flow handles all firmware-requested tx request types without transport-level "not implemented yet" errors |
| B. Configurable reliability controls | Expose retry/backoff/session timeout policy from `hw-wallet` through `hw-ffi` and `HWCoreConfig` | Core/FFI agent | App can tune retry attempts/delays/timeouts without code changes in Rust internals |
| C. Apple hardening | Add iOS UI smoke tests and lifecycle interruption recovery tests; document manual matrix | Apple agent | Green iOS smoke suite + documented manual matrix committed in `docs/` |
| D. Android sample app | Create minimal Android sample (Kotlin) wired to generated bindings: scan, connect, pair, get address, sign tx | Android agent | Runnable Gradle project under `android/` with README and one end-to-end happy-path demo flow |
| E. CI + docs alignment | Add CI jobs/commands for Apple + Android sample validation and keep roadmap/plans in sync | DevEx agent | CI proves bindings + sample builds, and docs reflect actual tested paths |

Execution order:
1. A + B in parallel (protocol capability + configuration surface).
2. D starts with ETH path first, then expands to BTC/SOL after A stabilizes.
3. C runs in parallel with D for mobile QA maturity.
4. E follows as soon as A/B/C/D land baseline automation hooks.

## Longer-Term

- Additional transport abstractions beyond BLE.
- Multi-vendor workflow abstraction beyond Trezor profile.
- Broader integration test matrix (device states, reconnect chaos testing).
