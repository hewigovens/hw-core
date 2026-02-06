# CLI Wallet v1 Execution Plan and Task Tracker (Trezor Safe 7)

Last updated: 2026-02-06
Status legend: TODO | IN_PROGRESS | BLOCKED | DONE

## Mission
Deliver an interactive CLI that can, with a real Trezor Safe 7 over BLE:
1. Connect and pair
2. Read an Ethereum address
3. Sign an Ethereum transaction

Priorities:
- Chain focus: Ethereum only for v1
- UX focus: human-friendly terminal flow first, machine-JSON output later

## Scope
In scope:
- BLE discovery and connection to Safe 7
- THP handshake and pairing (QR, NFC, code entry)
- Session creation
- Ethereum address retrieval
- Ethereum transaction signing
- Local persistence for host static key and pairing credentials

Out of scope:
- BTC/Cardano or multi-chain workflow beyond extension hooks
- USB transport
- Full automation-first non-interactive UX

## Current Baseline (Repo Audit)
- [x] `trezor-connect` supports THP create-channel, handshake, pairing, and session creation over BLE.
- [x] Local persistence exists via `ThpStorage` and `FileStorage` in `crates/trezor-connect/src/thp/storage.rs`.
- [x] BLE workflow example exists in `crates/trezor-connect/examples/ble_handshake.rs`.
- [x] Workspace task helpers exist in `justfile` (`scan-demo`, `workflow-demo`).
- [x] CLI crate `crates/hw-cli` exists with `scan`, `pair`, `address eth`, and `sign eth` command surface.
- [x] CLI `--pairing-method` currently supports `ble` only.
- [x] CLI `pair` timeout is configurable via `--timeout-secs` (default: `30`).
- [ ] ETH address/signing flows are not implemented in host workflow/backend.
- [ ] `address eth` and `sign eth` are scaffolded as explicit not-implemented stubs pending P3/P4.
- [ ] End-to-end CLI tests for `scan -> pair -> address -> sign` do not exist yet.

## Phase Gates
1. P0 Protocol contract ready: ETH message contract and protobuf source are confirmed.
2. P1 CLI skeleton ready: `hw-cli` builds and command help works for all v1 commands.
3. P2 Pairing UX ready: manual pair works and re-run reuses stored credentials.
4. P3 Address flow ready: `address eth` returns a checksummed address from a paired device.
5. P4 Signing flow ready: `sign eth` returns signature data and local verification output.
6. P5 Hardening ready: tests pass and manual smoke checklist is green on hardware.

## Task Tracker

### P0 - Protocol Contract and Design
- [x] `P0-01` Audit current implementation and identify done vs missing v1 pieces. `DONE`
- [ ] `P0-02` Confirm ETH wire contract for address/sign (message IDs, payload schema, chunking rules). `BLOCKED`
- [ ] `P0-03` Add or vendor required protobuf definitions for ETH flows. `TODO`
- [ ] `P0-04` Define CLI input/output schema for `sign eth` (required fields, output fields, error shape). `TODO`

Exit criteria:
- ETH address/sign protocol is documented and implementable without guessing firmware behavior.

### P1 - CLI Skeleton (`crates/hw-cli`)
- [x] `P1-01` Create `crates/hw-cli` and add it to workspace members in `Cargo.toml`. `DONE`
- [x] `P1-02` Add command surface with `clap`: `scan`, `pair`, `address eth`, `sign eth`. `DONE`
- [x] `P1-03` Add shared CLI config path and storage bootstrap logic. `DONE`
- [x] `P1-04` Wire BLE discovery/connection for `scan` command output. `DONE`
- [x] `P1-05` Add root `just` helpers for CLI dev loops. `DONE`

Exit criteria:
- `cargo run -p hw-cli -- --help` and subcommand help work for all v1 commands.

### P2 - Pairing UX and Persistence
- [x] `P2-01` Implement interactive `PairingController` with method-specific prompts. `DONE`
- [x] `P2-02` Implement `pair` command end-to-end using `ThpWorkflow` + storage. `DONE`
- [x] `P2-03` Add `pair --force` to clear/recreate credential path safely. `DONE`
- [x] `P2-04` Ensure re-run path uses saved static key and credentials by default. `DONE`
- [x] `P2-05` Make pair timeout configurable and raise default to 30s. `DONE`
- [ ] `P2-06` Add focused tests for pairing command state transitions and storage reuse. `TODO`

Exit criteria:
- First run pairs manually; second run avoids re-pair unless `--force`.

### P3 - Ethereum Address Flow
- [ ] `P3-01` Add ETH address request/response types in `crates/trezor-connect/src/thp/types.rs`. `TODO`
- [ ] `P3-02` Extend `ThpBackend` trait for ETH address operation. `TODO`
- [ ] `P3-03` Add proto encode/decode mapping in `crates/trezor-connect/src/thp/proto_conversions.rs`. `TODO`
- [ ] `P3-04` Implement encrypted BLE request/response handling in `crates/trezor-connect/src/ble.rs`. `TODO`
- [ ] `P3-05` Expose workflow API in `crates/trezor-connect/src/thp/workflow.rs`. `TODO`
- [ ] `P3-06` Wire CLI command `address eth --path <bip32>` with checksummed output formatting. `TODO`
- [ ] `P3-07` Add unit and integration tests for address mapping and command behavior. `TODO`

Exit criteria:
- `hw-cli address eth --path "m/44'/60'/0'/0/0"` returns a valid checksummed address from device.

### P4 - Ethereum Signing Flow
- [ ] `P4-01` Add ETH signing request/response and multi-step exchange support in host layer. `TODO`
- [ ] `P4-02` Implement BLE transport handling for sign flow (including chunking if required). `TODO`
- [ ] `P4-03` Add workflow method for signing transactions and surfacing device prompts. `TODO`
- [ ] `P4-04` Implement CLI `sign eth --path <bip32> --tx <file-or-json>`. `TODO`
- [ ] `P4-05` Validate tx input schema before device send. `TODO`
- [ ] `P4-06` Add local post-sign verification output where possible. `TODO`
- [ ] `P4-07` Add tests for happy path and common malformed input/device failure paths. `TODO`

Exit criteria:
- CLI prints signature payload from device and verification metadata for accepted tx input.

### P5 - Reliability, Validation, Docs
- [ ] `P5-01` Improve BLE timeout/retry strategy and classify actionable errors. `TODO`
- [ ] `P5-02` Add mocked integration tests for full command flow orchestration. `TODO`
- [ ] `P5-03` Run and document manual hardware smoke checklist:
  - `scan -> pair -> address eth -> sign eth`
  - repeated run without re-pair
  - forced re-pair flow
- [ ] `P5-04` Update root docs (`README.md`) with CLI usage and caveats. `TODO`

Exit criteria:
- Stable behavior across normal flow and common failure cases with documented recovery steps.

## Proposed v1 Command UX
- `hw-cli scan`
- `hw-cli pair --pairing-method ble --timeout-secs 30`
- `hw-cli address eth --path "m/44'/60'/0'/0/0"`
- `hw-cli sign eth --path "m/44'/60'/0'/0/0" --tx ./tx.json`

UX requirements:
- Clear step-by-step messaging for device actions
- Explicit confirmation prompts when user/device action is required
- Actionable errors instead of raw protocol dumps

## Risks and Dependencies
- ETH message details are the main critical path risk until protocol contract is confirmed.
- BLE behavior can require tuned retry/timeout values for stable UX on real hardware.
- Signing may require multi-message state handling rather than a single request/response.

## v1 Success Criteria
- A user can run the CLI on a real Trezor Safe 7 and complete:
  1. Pairing
  2. ETH address retrieval
  3. ETH transaction signing
- Re-running after pairing does not require manual pairing unless `pair --force` is used.
