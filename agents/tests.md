# Tests

- **Location.** Unit tests live in `#[cfg(test)] mod tests` at the bottom of the source file; larger suites go in a `tests.rs` sub-module (`ble/tests.rs`, `workflow/tests.rs`).
- **MockBackend.** Workflow tests use `MockBackend` in `trezor-connect/src/thp/workflow/tests.rs`: pick a scenario constructor (`autopair()`, `pairing_flow()`, `code_entry_flow()`, `paired_connection_flow()`), drive the workflow, then assert on requests the mock recorded (take it back with `workflow.into_parts()`).
- **Crypto vectors.** Test crypto against known vectors from Trezor Suite (e.g. the curve25519/elligator2 fixtures in `thp/crypto/curve25519.rs`).
- **Fixtures.** Store test data as JSON under `tests/data/<chain>/` and load it with `include_str!` using a path relative to the including file (`../../../tests/data/...` from `crates/<crate>/src`).
- **Roundtrips.** Prefer `proptest` for encode/decode roundtrips and boundary conditions when adding new codecs.
- **Naming.** State the scenario and outcome (`sign_flow_orchestrates_handshake_confirmation_and_session_retry`), not `test_sign`.
- **Filesystem state.** Use `tempfile::tempdir()`.
- **Emulator tests.** `#[ignore]`d BLE tests against the T3W1 emulator run in CI; see CONTRIBUTING.md.
