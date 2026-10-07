# Tests

## Test Location

Unit tests are inline in source files using `#[cfg(test)]` modules:

```rust
// good — bottom of the source file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encode_decode() { ... }
}
```

Integration tests that span multiple modules go in `tests.rs` sub-modules (e.g., `ble/tests.rs`, `workflow/tests.rs`).

## MockBackend Pattern

`MockBackend` (`trezor-connect/src/thp/workflow/tests.rs`) is built from scenario constructors (`autopair()`, `pairing_flow()`, `code_entry_flow()`, `paired_connection_flow()`) that set fixed response fields. Multi-step responses are queued in `Mutex<VecDeque<_>>`, and incoming requests are recorded in `parking_lot::Mutex` fields for later assertions:

```rust
// good — scenario constructor, then assert on recorded requests
let mut workflow = ThpWorkflow::new(MockBackend::autopair(), host_config);
workflow.create_channel().await.unwrap();
workflow.handshake(false).await.unwrap();
assert_eq!(workflow.state().phase(), Phase::Paired);

let (backend, _, _) = workflow.into_parts();
assert!(*backend.end_called.lock());
```

## Property-Based Testing

Prefer `proptest` for encode/decode roundtrips and boundary conditions when adding new codecs.

## Crypto Test Vectors

Always test crypto operations against known test vectors from Trezor Suite:

```rust
// good — elligator2 fixture test
#[test]
fn elligator2_matches_suite_vectors() {
    let input = hex::decode("...").unwrap();
    let expected = hex::decode("...").unwrap();
    assert_eq!(elligator2(&input), expected);
}
```

## JSON Test Fixtures

Store test data as JSON files under `tests/data/` and load with `include_str!()`:

```
tests/data/
  bitcoin/
    btc_parse_with_ref_txs.json
    btc_sign_with_ref_txs.json
  ethereum/
    eth_build_sign_request.json
    eip712_invalid_missing_domain_type.json
```

Paths are relative to the including source file (e.g. from `crates/hw-wallet/src/btc.rs`):

```rust
// good
const BTC_PARSE_WITH_REF_TXS: &str =
    include_str!("../../../tests/data/bitcoin/btc_parse_with_ref_txs.json");
```

## Test Naming

Use descriptive names that state the scenario and expected outcome:

```rust
// bad
#[test]
fn test_sign() { ... }

// good
#[test]
fn sign_flow_orchestrates_handshake_confirmation_and_session_retry() { ... }
```

## Temporary State in Tests

Use `tempfile` for tests that need filesystem state:

```rust
// good
let dir = tempfile::tempdir().unwrap();
let storage = FileStorage::new(dir.path().join("host.json"));
```
