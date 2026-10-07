# Error Handling

## Layered Error Types

Each crate boundary has its own `thiserror` error enum. Errors flow outward:

```
BackendError (trezor-connect)
  → ThpWorkflowError (trezor-connect)
    → WalletError (hw-wallet)
      → HWCoreError (hw-ffi, flattened to string for FFI)
```

The CLI top level uses `anyhow::Result`.

## No Panics in Production Code

Never use `unwrap()`, `expect()`, or `panic!()` on fallible operations in non-test code.

```rust
// bad — panics at runtime
let session = self.session.lock().expect("session must exist");

// good — return an error
let cache = self
    .state
    .handshake_cache()
    .ok_or(ThpWorkflowError::MissingHandshake)?;
```

For compile-time constants that are known to be valid, use `OnceLock` and validate in a test:

```rust
// good — thp/crypto/curve25519.rs
fn constants() -> &'static CurveConstants {
    static INSTANCE: OnceLock<CurveConstants> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let c3 = BigInt::parse_bytes(b"1968...", 10).expect("compile-time constant c3");
        // ...
    })
}
```

## Structured Error Variants

Do not classify errors by matching on message strings. Add structured variants instead.

```rust
// bad — breaks if message changes
fn is_retryable(err: &BackendError) -> bool {
    match err {
        BackendError::Device(msg) => msg.contains("device locked"),
        _ => false,
    }
}

// good — structured variants mapped from THP/Failure codes in one place
enum BackendError {
    TransportBusy, // THP error 1
    DeviceLocked,  // THP error 5
    DeviceBusy,    // Failure_Busy
    PinExpected,   // Failure_PinExpected
    DeviceError { code: u32, message: String },
    // ...
}

fn is_retryable_handshake_error(error: &ThpWorkflowError) -> bool {
    matches!(
        error,
        ThpWorkflowError::Backend(BackendError::DeviceLocked | BackendError::TransportBusy)
    )
}
```

## Error Type Design

Use `#[from]` for automatic conversion from inner errors. Add context with `.map_err()`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("invalid BIP32 path: {0}")]
    InvalidBip32Path(String),
    #[error("BLE error: {0}")]
    Ble(#[from] ble_transport::BleError),
    #[error("workflow error: {0}")]
    Workflow(#[from] trezor_connect::thp::ThpWorkflowError),
    #[error("signing error: {0}")]
    Signing(String),
    // ...
}
```
