# CLI Wallet v1 Execution Plan and Task Tracker (Trezor Safe 7)

Last updated: 2026-02-07
Status legend: TODO | IN_PROGRESS | BLOCKED | DONE

## Mission
Deliver a CLI that can, with a real Trezor Safe 7 over BLE:
1. Connect and pair
2. Read an Ethereum address
3. Sign an Ethereum transaction

Priorities:
- Chain focus: Ethereum only for v1
- UX focus: human-friendly terminal flow first, machine-JSON output later

## Scope
In scope:
- BLE discovery and connection to Safe 7
- THP handshake and pairing (CodeEntry over BLE for v1)
- Session creation
- Ethereum address retrieval
- Ethereum transaction signing
- Local persistence for host static key and pairing credentials

Out of scope:
- BTC/Cardano or multi-chain workflow beyond extension hooks
- Additional non-BLE transports
- Full automation-first non-interactive UX

## Current Baseline (Repo Audit)
- [x] `trezor-connect` supports THP create-channel, handshake, pairing, and session creation over BLE.
- [x] Local persistence exists via `ThpStorage` and `FileStorage` in `crates/trezor-connect/src/thp/storage.rs`.
- [x] BLE workflow example exists in `crates/trezor-connect/examples/ble_handshake.rs`.
- [x] Workspace task helpers exist in `justfile` (`scan-demo`, `workflow-demo`).
- [x] CLI crate `crates/hw-cli` exists with `scan`, `pair`, `address --chain`, and `sign eth` command surface.
- [x] CLI `--pairing-method` currently supports `ble` only.
- [x] CLI `pair` timeout is configurable via `--timeout-secs` (default: `60`).
- [x] THP response timeout is configurable via `--thp-timeout-secs` (default: `60`).
- [x] Pair flow retries `create-channel` on transient BLE timeout.
- [x] Pair/address scanning exits early when a matching device is discovered instead of always waiting full timeout.
- [x] CLI supports verbose debug logging via `-v` / `-vv`.
- [x] REPL session mode (`pair --interactive`) was implemented previously and has been removed to reduce maintenance.
- [x] BLE THP backend auto-acknowledges `ButtonRequest` with `ButtonAck` during encrypted flow.
- [x] Pair/address detect BLE "Peer removed pairing information" and show explicit OS unpair/removal recovery guidance.
- [x] CLI defaults host pairing preference to `CodeEntry` (aligned with Trezor Suite default) instead of accepting all methods implicitly.
- [x] Pair workflow tests cover storage snapshot load and persistence on handshake.
- [x] Pair host/app identity defaults to machine device name + `hw-core/cli`.
- [x] BLE session setup aligns closer with Trezor Suite by probing write-with-response (`"Proof of connection"`) and subscribing both `notify` and `push` characteristics.
- [x] BLE transport + THP backend include verbose TX/RX frame/chunk debug logs to diagnose channel-allocation stalls.
- [x] BLE protocol writes use GATT write-without-response (Suite parity) with fallback characteristic reads when notifications are silent.
- [x] Shared wallet BLE orchestration crate `crates/hw-wallet` exists and is wired into `hw-cli` and `hw-ffi`.
- [x] Shared BIP32 parser moved to `crates/hw-wallet` for reuse by CLI/FFI.
- [x] Chain-generic host `get-address` API exists in THP layer (Ethereum implementation complete, extensible to more chains).
- [x] CLI `address --chain eth` is implemented and supports optional `--include-public-key`.
- [x] ETH signing flow is implemented in THP types/backend/proto conversions/BLE backend/workflow.
- [x] CLI `sign eth --path <bip32> --tx <json|@file>` is implemented.
- [x] ETH tx JSON parsing/building has been moved into shared `crates/hw-wallet` for CLI/FFI reuse.
- [x] Handshake `Paired` state now follows Suite-compatible connection-finalization flow (`CredentialRequest` + `EndRequest`) before session creation.
- [x] `address`/`sign`/`pair` handle paired-connection confirmation before `create_session`.
- [x] EIP-1559 sign protobuf mapping fixed (`chunkify` tag=13) to avoid firmware decode failure on `payment_req`.
- [x] Handshake transient busy/not-ready errors (e.g. device error code 5) now retry with fresh channel setup.
- [x] Local post-sign verification outputs tx hash + recovered Ethereum signer address.
- [x] Mocked orchestration tests cover address/sign command flow without hardware.
- [x] Retry and error normalization now include create-session transient busy/failure handling (error code 5/99).
- [x] Hardware smoke checklist is documented and kept for manual regression runs.

## Phase Gates
1. P0 Protocol contract ready: ETH message contract and protobuf source are confirmed.
2. P1 CLI skeleton ready: `hw-cli` builds and command help works for all v1 commands.
3. P2 Pairing UX ready: manual pair works and re-run reuses stored credentials.
4. P3 Address flow ready: `address --chain eth` returns a checksummed address from a paired device.
5. P4 Signing flow ready: `sign eth` returns signature data and local verification output.
6. P5 Hardening ready: tests pass and manual smoke checklist is green on hardware.

## Task Tracker

### P0 - Protocol Contract and Design
- [x] `P0-01` Audit current implementation and identify done vs missing v1 pieces. `DONE`
- [x] `P0-02` Confirm ETH wire contract for address/sign (message IDs, payload schema, chunking rules). `DONE`
- [x] `P0-03` Add or vendor required protobuf definitions for ETH flows. `DONE`
- [x] `P0-04` Define CLI input/output schema for `sign eth` (required fields, output fields, error shape). `DONE`

Exit criteria:
- ETH address/sign protocol is documented and implementable without guessing firmware behavior.

### P1 - CLI Skeleton (`crates/hw-cli`)
- [x] `P1-01` Create `crates/hw-cli` and add it to workspace members in `Cargo.toml`. `DONE`
- [x] `P1-02` Add command surface with `clap`: `scan`, `pair`, `address --chain`, `sign eth`. `DONE`
- [x] `P1-03` Add shared CLI config path and storage bootstrap logic. `DONE`
- [x] `P1-04` Wire BLE discovery/connection for `scan` command output. `DONE`
- [x] `P1-05` Add root `just` helpers for CLI dev loops. `DONE`
- [x] `P1-06` Extract shared BLE wallet orchestration into `crates/hw-wallet` and reuse it from `hw-cli` + `hw-ffi`. `DONE`
- [x] `P1-07` Move shared BIP32 derivation-path parsing into `crates/hw-wallet` to avoid CLI-only duplication. `DONE`

Exit criteria:
- `cargo run -p hw-cli -- --help` and subcommand help work for all v1 commands.

### P2 - Pairing UX and Persistence
- [x] `P2-01` Implement interactive `PairingController` with method-specific prompts. `DONE`
- [x] `P2-02` Implement `pair` command end-to-end using `ThpWorkflow` + storage. `DONE`
- [x] `P2-03` Add `pair --force` to clear/recreate credential path safely. `DONE`
- [x] `P2-04` Ensure re-run path uses saved static key and credentials by default. `DONE`
- [x] `P2-05` Make pair timeout configurable and raise default to 60s. `DONE`
- [x] `P2-06` Add focused tests for pairing command state transitions and storage reuse. `DONE`
- [x] `P2-07` Add verbose pairing logs and handle THP `ButtonRequest`/`ButtonAck` continuation flow. `DONE`
- [x] `P2-08` Add configurable THP timeout and retry for create-channel timeout recovery. `DONE`
- [x] `P2-09` `pair --interactive` REPL session mode was added and later removed to reduce maintenance. `DONE`
- [x] `P2-10` REPL autocomplete was added and later removed with REPL removal. `DONE`

Exit criteria:
- First run pairs manually; second run avoids re-pair unless `--force`.

### P3 - Ethereum Address Flow
- [x] `P3-01` Add ETH address request/response types in `crates/trezor-connect/src/thp/types.rs`. `DONE`
- [x] `P3-02` Extend `ThpBackend` trait for ETH address operation. `DONE`
- [x] `P3-03` Add proto encode/decode mapping in `crates/trezor-connect/src/thp/proto.rs`. `DONE`
- [x] `P3-04` Implement encrypted BLE request/response handling in `crates/trezor-connect/src/ble.rs`. `DONE`
- [x] `P3-05` Expose workflow API in `crates/trezor-connect/src/thp/workflow.rs`. `DONE`
- [x] `P3-06` Wire CLI command `address` with `--chain <eth|btc>` and default-path fallback (`m/44'/60'/0'/0/0` for eth) plus checksummed output formatting. `DONE`
- [x] `P3-07` Add unit tests for address mapping and command behavior. `DONE`
- [x] `P3-08` Add integration tests for address command orchestration with mocked THP backend. `DONE`

Exit criteria:
- `hw-cli address --chain eth` returns a valid checksummed address from device.

### P4 - Ethereum Signing Flow
- [x] `P4-01` Add ETH signing request/response and multi-step exchange support in host layer. `DONE`
- [x] `P4-02` Implement BLE transport handling for sign flow (including chunking if required). `DONE`
- [x] `P4-03` Add workflow method for signing transactions and surfacing device prompts. `DONE`
- [x] `P4-04` Implement CLI `sign eth --path <bip32> --tx <file-or-json>`. `DONE`
- [x] `P4-05` Validate tx input schema before device send. `DONE`
- [x] `P4-06` Add local post-sign verification output where possible. `DONE`
- [x] `P4-07` Add tests for request mapping and malformed input paths. `DONE`

Exit criteria:
- CLI prints signature payload from device and verification metadata for accepted tx input.

### P5 - Reliability, Validation, Docs
- [x] `P5-01` Improve BLE timeout/retry strategy and classify actionable errors. `DONE`
  - Implemented: create-channel retry, handshake busy retry, create-session transient retry, peer-unpaired actionable messaging, firmware-busy normalization.
- [x] `P5-02` Add mocked integration tests for full command flow orchestration. `DONE`
- [x] `P5-03` Run and document manual hardware smoke checklist:
  - `scan -> pair -> address --chain eth -> sign eth`
  - repeated run without re-pair
  - forced re-pair flow
- [x] `P5-04` Update root docs (`README.md`) with CLI usage and caveats. `DONE`

Exit criteria:
- Stable behavior across normal flow and common failure cases with documented recovery steps.

## Proposed v1 Command UX
- `hw-cli scan`
- `hw-cli pair --pairing-method ble --timeout-secs 60 --thp-timeout-secs 60`
- `hw-cli address --chain eth --include-public-key` (auto-runs pairing prompt if device is not paired)
- `hw-cli address --path "m/44'/60'/0'/0/0"` (chain inferred/defaulted from path)
- `hw-cli sign eth --path "m/44'/60'/0'/0/0" --tx ./tx.json` (auto-runs pairing prompt if device is not paired)
- `just cli-sign-eth` (quick signing smoke helper with inline EIP-1559 JSON)
- Debug mode: add `-v`/`-vv` before command, e.g. `hw-cli -vv pair --pairing-method ble --timeout-secs 60`

UX requirements:
- Clear step-by-step messaging for device actions
- Explicit confirmation prompts when user/device action is required
- Actionable errors instead of raw protocol dumps

## Risks and Dependencies
- ETH message details are the main critical path risk until protocol contract is confirmed.
- BLE behavior can require tuned retry/timeout values for stable UX on real hardware.
- Signing may require multi-message state handling rather than a single request/response.

## Trezor Suite References (Source of Truth When Unsure)
Use local clone at:
- `~/workspace/github/trezor-suite`

Primary references:
- THP + message IDs/schema: `trezor-suite/packages/protobuf/messages.json`
- Ethereum address flow in Connect: `trezor-suite/packages/connect/src/api/ethereum/api/ethereumGetAddress.ts`
- Generic BTC-style address flow: `trezor-suite/packages/connect/src/api/getAddress.ts`
- Public key flow: `trezor-suite/packages/connect/src/api/getPublicKey.ts`
- BLE peer-unpaired handling in Suite: `trezor-suite/packages/suite/src/actions/bluetooth/bluetoothConnectDeviceThunk.ts`
- BLE native pairing-error mapping: `trezor-suite/packages/transport-native-bluetooth/src/api/bluetoothManager.ts`
- User-facing OS unpair guidance string: `trezor-suite/packages/suite-data/files/translations/en-US.json`

Rule:
- If expected device behavior or protocol details are unclear, check these files first and align implementation/UX with Suite semantics before introducing custom behavior.

## v1 Success Criteria
- A user can run the CLI on a real Trezor Safe 7 and complete:
  1. Pairing
  2. ETH address retrieval
  3. ETH transaction signing
- Re-running after pairing does not require manual pairing unless `pair --force` is used.

## Manual Hardware Smoke Checklist (P5-03)

Preconditions:
- Trezor Safe 7 is powered on and unlocked.
- If the host reports pairing mismatch (`Peer removed pairing information`), remove the device from OS Bluetooth settings first.
- Host storage file is available at `~/.hw-core/thp-host.json`.

Commands:
1. Scan:
   - `just cli-scan`
   - Expect at least one `Trezor Safe 7` candidate.
2. Pair:
   - `just cli-pair`
   - Confirm connection/pairing on device when prompted.
   - Enter 6-digit code-entry challenge.
   - Expect `Pairing complete.` and persisted host state path.
3. Address:
   - `just cli-address-eth`
   - Expect `Address: 0x...` and optional `Public key: ...`.
4. Sign:
   - `just cli-sign-eth`
   - Confirm prompts on device.
   - Expect `v`, `r`, `s`, plus local verification output:
     - `tx_hash: 0x...`
     - `recovered_address: 0x...`
5. Repeat address/sign without re-pair:
   - Re-run steps 3 and 4.
   - Expect success without a full pairing flow.
6. Forced re-pair:
   - `cargo run -p hw-cli -- -vv pair --force`
   - Expect storage reset followed by successful pairing.

Failure recovery notes:
- `Peer removed pairing information`:
  - Remove Trezor from OS Bluetooth settings, then run pair with `--force`.
- `device returned error code 5`:
  - Device not ready/busy; wait for device prompt/unlock and retry.
- `device returned error code 99`:
  - Firmware busy/transient state; keep device unlocked and retry.
