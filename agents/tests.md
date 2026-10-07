# Tests

## Validation

- Choose the smallest layer that proves the changed contract. Use `cargo test -p <crate-name> <test_name>` during implementation; select `--lib` or `--test <target>` when needed and inspect the test count. Zero matching tests or ignored tests are not passing coverage.
- Bug fixes include a regression test that fails on the pre-fix code for the intended reason and passes after the fix.
- Before adding a test, identify its observable behavior, a credible regression, and why existing coverage does not catch it. Extend an existing fixture or table when it covers the same contract.
- Assert requests, state transitions, errors, or persisted outcomes at the owning layer. Avoid expectations produced by the code under test and mocks that implement the behavior being asserted.
- Add CLI, FFI, Swift, or Kotlin coverage for independent argument conversion, marshalling, interaction, or lifecycle risks rather than duplicating core assertions.
- Cover distinct failure modes where relevant: disconnect during an operation, cancellation, stale completion after reconnect, bounded retries, malformed input, and storage failure.
- Report deterministic tests, emulator runs, physical-device checks, and platform/binding checks separately, including skipped or blocked checks. Binding generation alone does not prove a consumer compiles; simulator UI success does not prove physical BLE behavior.
- Use the formatting and documentation validation rules in [AGENTS.md](../AGENTS.md#formatting-mandatory), and the publication gate in [Commit Guidelines](commit-guidelines.md).

## Fixtures and Organization

- **Location.** Unit tests live in `#[cfg(test)] mod tests` at the bottom of the source file; larger suites go in a `tests.rs` sub-module (`ble/tests.rs`, `workflow/tests.rs`).
- **MockBackend.** All crates share `trezor_connect::thp::testing::MockBackend` (enable the `test-support` feature in `[dev-dependencies]`): pick a scenario constructor (`autopair()`, `pairing_flow()`, `code_entry_flow()`, `paired_connection_flow()`), adjust its public fields, drive the workflow, then assert on the recorded requests and counters (via `workflow.backend_mut()` or `workflow.into_parts()`).
- **Crypto vectors.** Test crypto against known vectors from Trezor Suite (e.g. the curve25519/elligator2 fixtures in `thp/crypto/curve25519.rs`).
- **Fixtures.** Store test data as JSON under `tests/data/<chain>/` and load it with `include_str!` using a path relative to the including file (`../../../tests/data/...` from `crates/<crate>/src`).
- **Roundtrips.** Prefer `proptest` for encode/decode roundtrips and boundary conditions when adding new codecs.
- **Naming.** State the scenario and outcome (`sign_flow_orchestrates_handshake_confirmation_and_session_retry`), not `test_sign`.
- **Filesystem state.** Use `tempfile::tempdir()`.
- **Emulator tests.** `#[ignore]`d BLE tests against the T3W1 emulator run in CI; see CONTRIBUTING.md.
