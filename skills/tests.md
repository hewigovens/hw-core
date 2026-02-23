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

Use `MockBackend` with `parking_lot::Mutex<VecDeque<Response>>` for canned responses:

```rust
// good — queue expected responses, assert call counts
let mock = MockBackend::new();
mock.queue_response(Response::HandshakeOk);
mock.queue_response(Response::PairingOk);

let workflow = ThpWorkflow::new(mock);
workflow.connect().await.unwrap();

assert_eq!(mock.call_count("create_channel"), 1);
assert_eq!(mock.call_count("handshake"), 1);
```

## Property-Based Testing

Use `proptest` for encode/decode roundtrip tests and boundary conditions:

```rust
// good — thp-crypto frame roundtrip
proptest! {
    #[test]
    fn frame_roundtrip(payload in prop::collection::vec(any::<u8>(), 0..4096)) {
        let encoded = encode_frame(&payload);
        let decoded = decode_frame(&encoded).unwrap();
        prop_assert_eq!(decoded, payload);
    }
}
```

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
  ethereum/
    eth_sign_request.json
  eip712/
    typed_data.json
```

```rust
// good
let json = include_str!("../tests/data/bitcoin/btc_parse_with_ref_txs.json");
let fixture: BtcFixture = serde_json::from_str(json).unwrap();
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
