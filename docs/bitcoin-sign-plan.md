# Bitcoin Signing Completion Plan

## Goal
Finish BTC signing for the current app/CLI flow by implementing previous-transaction request handling (`TXMETA`, `TXINPUT`, `TXOUTPUT`, `TXEXTRADATA`) in the THP signing loop.

## Scope (v1)
- Support standard signing flows that require referenced previous transactions.
- Add a stable request format for referenced transaction data.
- Keep current `TXORIGINPUT`, `TXORIGOUTPUT`, and `TXPAYMENTREQ` out of scope for v1.

## Work Items
1. Request model updates
- Extend BTC sign payload model with `ref_txs`.
- Each referenced tx must include enough data for Trezor requests:
  - `hash`, `version`, `lock_time`
  - `inputs` (prev hash/index, sequence, `script_sig`)
  - `bin_outputs` (amount, `script_pubkey`)
  - optional `extra_data`
  - optional future fields (`timestamp`, `version_group_id`, `expiry`, `branch_id`)

2. Wallet parsing/validation
- Update `/Users/hewig/workspace/hw-core/crates/hw-wallet/src/btc.rs` JSON parser to accept and validate `ref_txs`.
- Enforce that every signing input `prev_hash` has a matching referenced tx.
- Validate indexed access safety (request index bounds for prev inputs/outputs).

3. THP proto mapping
- Update `/Users/hewig/workspace/hw-core/crates/trezor-connect/src/thp/proto.rs`:
  - Add `TxAck` encoding helpers for previous tx meta/input/output/extra-data chunk.
  - Add message fields needed for prev output responses (`bin_outputs`/`script_pubkey` path).

4. Signing state machine
- Update `/Users/hewig/workspace/hw-core/crates/trezor-connect/src/ble.rs` BTC sign loop:
  - If `tx_hash` is set in `TxRequest.details`, route to previous-tx responder.
  - Dispatch by request type:
    - `TXMETA` -> previous tx meta
    - `TXINPUT` -> previous tx input
    - `TXOUTPUT` -> previous tx binary output
    - `TXEXTRADATA` -> chunked extra data response
  - Keep clear errors for unsupported request types (orig/payment request) in v1.

5. FFI and sample app
- Expose new BTC JSON contract through existing FFI sign request path.
- Update sample BTC JSON fixture to include realistic `ref_txs` example.

## Tests
1. Proto tests
- Encode/decode tests for all new prev-tx ack shapes.

2. Wallet tests
- JSON parsing tests for valid/invalid `ref_txs`.
- Missing referenced tx should return a validation error.

3. Backend tests
- Mock `TxRequest` sequence that includes prev-tx requests and assert successful completion.
- Add negative tests for unknown hash and out-of-bounds request index.

## Acceptance Criteria
- BTC signing no longer fails with `previous-transaction metadata requests are not implemented yet`.
- CLI and sample app can sign a BTC fixture with valid `ref_txs`.
- Unsupported advanced request types still fail with explicit, actionable errors.
