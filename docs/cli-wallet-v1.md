# CLI Wallet v1 Plan (Trezor Safe 7)

## Goal
Deliver a CLI that can, with a real Trezor Safe 7 over BLE:
1. Connect
2. Pair
3. View ETH address
4. Sign ETH transaction

Priorities:
- Chain focus: Ethereum first
- UX focus: human-friendly interactive CLI first (JSON output optional later)

## Scope
In scope for v1:
- BLE discovery + connection to Safe 7
- THP handshake + pairing (QR / NFC / code entry)
- Session creation
- Ethereum address retrieval
- Ethereum transaction signing
- Local persistence for host static key + pairing credentials

Out of scope for v1:
- Multi-chain support (BTC/Cardano) beyond design hooks
- USB transport
- Full non-interactive automation-first UX

## Milestones

### Milestone 1: CLI skeleton and command surface
Create `crates/hw-cli` with initial commands:
- `scan`
- `pair`
- `address eth`
- `sign eth`

Implementation notes:
- Use `trezor-connect` directly (faster iteration than FFI path)
- Use a command parser (`clap`) and interactive prompts for human UX
- Add root `just` helpers for common CLI flows

Deliverable:
- CLI binary builds and shows usable command help and prompts

### Milestone 2: Pairing UX and persistence
Wire pairing flow end-to-end in CLI:
- Implement interactive `PairingController`
- Show clear prompts per method (QR/NFC/code-entry)
- Persist host config and credentials using `thp::storage`
- Add explicit re-pair/reset option (`pair --force`)

Deliverable:
- First run can pair manually; subsequent runs can reuse stored credentials

### Milestone 3: Ethereum address support in trezor-connect
Extend THP host layer for ETH address retrieval:
- Add request/response types in `crates/trezor-connect/src/thp/types.rs`
- Add backend trait methods in `crates/trezor-connect/src/thp/backend.rs`
- Implement encrypted BLE message handling in `crates/trezor-connect/src/ble.rs`
- Add protobuf encode/decode mapping in `crates/trezor-connect/src/thp/proto_conversions.rs`
- Expose workflow API in `crates/trezor-connect/src/thp/workflow.rs`

CLI behavior:
- `address eth --path <bip32>` prints checksummed address with clear labels

Deliverable:
- Address retrieval works on paired device from CLI

### Milestone 4: Ethereum transaction signing
Implement ETH signing flow:
- Add THP request/response path for ETH signing messages
- Handle multi-step/chunked message exchanges if required
- CLI command accepts tx input (file/string), validates, sends to device, prints signature

CLI behavior:
- `sign eth --tx <file-or-json> --path <bip32>`
- User confirmations clearly surfaced in terminal

Deliverable:
- Signed result from device, with local verification output where possible

### Milestone 5: Reliability and validation
Testing and hardening:
- Unit tests for proto conversions and workflow methods
- Integration tests with mocked wire/backend for command flows
- Manual hardware smoke checklist: `scan -> pair -> address -> sign`
- Improve errors/timeouts/retries for BLE and user prompts

Deliverable:
- Stable CLI behavior for normal and common failure paths

## Proposed command UX (human-first)
- `hw-cli scan`
- `hw-cli pair`
- `hw-cli address eth --path "m/44'/60'/0'/0/0"`
- `hw-cli sign eth --path "m/44'/60'/0'/0/0" --tx ./tx.json`

UX expectations:
- Clear step-by-step terminal messaging
- Explicit confirmation prompts where user action is required
- Friendly actionable errors (not raw protocol dumps)

## Repository changes expected
- New crate: `crates/hw-cli`
- Extend existing THP host code in:
  - `crates/trezor-connect/src/thp/types.rs`
  - `crates/trezor-connect/src/thp/backend.rs`
  - `crates/trezor-connect/src/thp/proto_conversions.rs`
  - `crates/trezor-connect/src/thp/workflow.rs`
  - `crates/trezor-connect/src/ble.rs`
- Optional docs updates in root `README.md`

## Execution order
1. Build CLI skeleton (`scan`, `pair`) and persistence
2. Implement ETH address retrieval in `trezor-connect` + CLI
3. Implement ETH signing in `trezor-connect` + CLI
4. Add tests, smoke checks, and docs polish

## Risks and notes
- THP ETH message details may require additional proto coverage or firmware-specific handling
- BLE reliability and device timing can require tuned retries/timeouts
- Signing may involve multi-message state transitions beyond simple request/response

## Success criteria
- User can run CLI against Trezor Safe 7 and complete:
  1. Pairing
  2. ETH address retrieval
  3. ETH transaction signing
- Re-running commands after pairing does not require repeating manual pairing unless forced
