# Bitcoin Signing Plan (Status)

## Goal
Complete BTC signing for current app/CLI flow by handling previous-transaction requests in the THP signing loop.

## Scope
- `v1` (completed): `TXMETA`, `TXINPUT`, `TXOUTPUT`, `TXEXTRADATA` for previous transactions using `ref_txs`.
- `v2` (remaining): `TXORIGINPUT`, `TXORIGOUTPUT`, `TXPAYMENTREQ`.

## Current Status (2026-02-19)

### Completed (`v1`)
1. Request model and payload contract
- `ref_txs` is supported in BTC sign JSON.
- Referenced tx data supports:
  - `hash`, `version`, `lock_time`
  - `inputs` (`prev_hash`, `prev_index`, `sequence`, `script_sig`)
  - `bin_outputs` (`amount`, `script_pubkey`)
  - optional `extra_data`, `timestamp`, `version_group_id`, `expiry`, `branch_id`

2. Wallet parsing and validation
- BTC parser accepts and validates `ref_txs`.
- Every signing input `prev_hash` must exist in `ref_txs`.
- Bounds checks are enforced for requested referenced outputs.
- Duplicate `ref_txs` hashes are rejected.

3. THP proto mapping
- Added previous-tx ACK encoders for:
  - prev meta
  - prev input
  - prev output (`bin_outputs`)
  - prev extra-data chunk
- Added missing proto fields required by these responses.

4. Signing state machine
- BTC sign loop routes requests by `tx_hash` presence:
  - `TXMETA` -> referenced tx meta
  - `TXINPUT` -> referenced tx input
  - `TXOUTPUT` -> referenced tx binary output
  - `TXEXTRADATA` -> referenced tx extra-data chunk
- Unsupported types remain explicit errors:
  - `TXORIGINPUT`, `TXORIGOUTPUT`, `TXPAYMENTREQ`

5. FFI and sample data
- Existing FFI sign path supports the updated BTC JSON contract.
- Sample/default BTC JSON now includes `ref_txs`.

6. Tests and test data
- Added proto tests for prev-tx ACK payloads.
- Added wallet tests for `ref_txs` success and validation failures.
- Added backend tests for unknown hash and out-of-bounds index errors.
- Moved BTC/ETH test JSON payloads to `tests/data/...` and updated tests to load from files.

7. Proto code organization
- Split `thp/proto.rs` into:
  - `thp/proto/mod.rs` (shared/pairing)
  - `thp/proto/bitcoin.rs`
  - `thp/proto/ethereum.rs`
  - `thp/proto/solana.rs`
- Kept the external `thp::proto::*` API stable via re-exports.

## Remaining Work (`v2`)
1. Implement `TXORIGINPUT` flow.
2. Implement `TXORIGOUTPUT` flow.
3. Implement `TXPAYMENTREQ` flow.
4. Add integration tests covering mixed `TX*` sequences including orig/payment requests.

## Acceptance Criteria
- `v1` status: met.
- `v2` status: pending on `TXORIG*` and `TXPAYMENTREQ`.
