# hw-core Execution Plan

Last updated: 2026-03-09
Status legend: TODO | IN_PROGRESS | DONE | BLOCKED

## Objective
Ship a stable, well-documented library that external developers can integrate through Rust, CLI, and FFI surfaces without needing to reverse-engineer behavior from sample apps or source code.

## What Counts as "Dev Ready"
- Core wallet flows succeed reliably on supported platforms: scan, pair, reconnect, address, sign-tx, sign-message.
- Public request/response behavior is stable, documented, and covered by tests.
- Android and Apple consumers have a supported integration path, not just sample apps.
- CI and smoke checks prove the flows we claim to support.

## Active Priorities

## Protocol Completeness and API Stability
Status: IN_PROGRESS
Owner: Core/Protocol

### Why This Is Critical
If protocol handling or request validation is incomplete, every consumer surface inherits undefined behavior. This is the highest-priority blocker to adoption.

### Completed
- `ref_txs` request model, validation, and prev-tx payload support.
- Implemented handling for `TXMETA`, `TXINPUT`, `TXOUTPUT`, and `TXEXTRADATA`.
- Implemented handling for `TXORIGINPUT`, `TXORIGOUTPUT`, and `TXPAYMENTREQ`.
- Added `BtcPaymentRequest` / `BtcPaymentRequestMemo` types and `TxAckPaymentRequest` encoding.
- Added `get_nonce` support through THP proto, backend, workflow, and FFI layers.
- Added unit coverage for the new BTC request types, bounds checks, and nonce flows.

### Must Finish
- [ ] Add integration tests for mixed BTC `TX*` request sequences.
- [ ] Validate BTC payment-request signing on real hardware with a live server-signed SLIP-24 request, fresh nonce, and authenticated MACs.
- [ ] Extract message-signing validation into a shared module used by all entry points.
- [ ] Add negative fixtures for malformed ETH mode combinations and EIP-712 payloads.
- [ ] Remove duplicated request-validation logic across CLI, wallet, and FFI.
- [ ] Add focused regression tests before and after the validation refactor.

### Exit Criteria
- No known protocol gaps remain in the supported ETH/BTC flows.
- Consumer-facing inputs are validated consistently regardless of entry point.
- Error behavior is structured and predictable enough for app developers to handle.

## Consumer Surface Readiness
Status: IN_PROGRESS
Owner: FFI/DevEx

### Why This Is Critical
The library is not developer-ready until third-party app teams can consume it without depending on repo internals or manually reproducing sample-app setup.

### Includes
- Keep Apple and Android sample flows aligned with the actual supported library contract.
- Package the library for downstream consumption.
- Document the supported integration path for Android and Apple consumers.

### Must Finish
- [ ] Verify repeated real-device happy paths on Android: pair, connect, address, sign, disconnect, reconnect.
- [ ] Add focused Apple regressions for stale pairing credentials and reconnect recovery.
- [ ] Keep instrumentation/UI smoke coverage for app launch and primary sample controls current.
- [ ] Android: add `maven-publish` support for `android/lib`.
- [ ] iOS/macOS: build and package `HWCore.xcframework`.
- [ ] Add versioned release artifacts for Android and Apple outputs.
- [ ] Write consumer integration guides for Android and iOS/macOS that do not depend on reading sample-app code.

### Exit Criteria
- A developer can integrate hw-core from published artifacts on Android and Apple platforms.
- Sample apps prove the supported flows, but are no longer the only integration reference.

## Validation, CI, and Release Gates
Status: IN_PROGRESS
Owner: DevEx

### Why This Is Critical
Without a narrow validation story, "supported" behavior will keep drifting from reality and developers will discover breakage late.

### Includes
- Keep the validation matrix small and explicit.
- Make CI reflect the real support contract.
- Keep docs current with the validated developer experience.

### Must Finish
- [ ] Define one canonical smoke matrix for CLI, Apple, and Android flows.
- [ ] Add CI coverage for Apple sample build and smoke checks where runner support exists.
- [ ] Keep Android sample build validation in CI and extend it with the minimum high-signal checks.
- [ ] Update `README.md` and contributor docs so all referenced commands still work.
- [ ] Keep `docs/plan.md` and `docs/roadmap.md` synchronized as the only active planning docs.
- [ ] Create a release checklist covering bindings, artifacts, smoke tests, and docs verification.

### Exit Criteria
- CI validates the flows we claim are supported.
- Release readiness can be assessed from one documented checklist instead of tribal knowledge.

## Deferred Until After Developer Readiness
- Broader sample-app UX polish beyond the core integration path.
- Additional chain expansion beyond currently supported flows.
- New transport abstractions or multi-vendor wallet support.
- Large-scale refactors that do not materially reduce consumer risk.

## Release Gate
The library is ready for broader developer use when all items below are true:

- [ ] `just ci` passes.
- [ ] CLI happy-path smoke checks pass for scan, pair, address, sign-tx, and sign-message.
- [ ] BTC advanced signing coverage is complete for the supported firmware request sequence.
- [ ] BTC SLIP-24 payment-request signing is exercised against real hardware and a real signing backend.
- [ ] Apple sample smoke checks pass for the documented happy path.
- [ ] Android sample happy-path checks pass on a real device across repeated runs.
- [ ] Android and Apple artifacts can be produced from documented commands.
- [ ] Consumer integration docs match the current released API and packaging model.

## Risks
- Real-device validation still matters for payment requests even though fixture-based support is now implemented.
- BLE reconnect behavior remains sensitive to platform differences and pairing state.
- Packaging work can expose API sharp edges that are currently hidden by in-repo sample apps.
- If validation stays broader than the supported matrix, CI cost will rise without increasing confidence.
