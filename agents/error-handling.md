# Error Handling

## Layered Error Types

Each crate boundary has its own `thiserror` enum. Errors flow outward:

```
BackendError (trezor-connect)
  → ThpWorkflowError (trezor-connect)
    → WalletError (hw-wallet)
      → HWCoreError (hw-ffi, flattened to string for FFI)
```

The CLI top level uses `anyhow::Result`.

## Rules

- **No panics in production code.** No `unwrap()`, `expect()` or `panic!()` on fallible operations outside tests; return an error (e.g. `ok_or(ThpWorkflowError::MissingHandshake)?`).
- **Compile-time constants** that must be parsed go in a `OnceLock` with a test that forces initialization (see `constants()` in `thp/crypto/curve25519.rs`).
- **Structured variants, not strings.** Never classify errors by matching message text. Map protocol codes to variants in one place (THP transport errors and `Failure` codes in `trezor-connect/src/ble/errors.rs`) and match on variants, as `is_retryable_handshake_error` in `hw-wallet/src/ble.rs` does.
- **Conversions.** Use `#[from]` for wrapping inner errors and `.map_err()` to add context.
