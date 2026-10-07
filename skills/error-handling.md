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
let session = self.session.lock();
let session = session.as_ref().ok_or(TransportError::NoSession)?;
```

For compile-time constants that are known to be valid, use `OnceLock` and validate in a test:

```rust
// bad
let params = "Noise_XX_25519_AESGCM_SHA256".parse().unwrap();

// good
static NOISE_PARAMS: OnceLock<NoiseParams> = OnceLock::new();
let params = NOISE_PARAMS.get_or_init(|| {
    "Noise_XX_25519_AESGCM_SHA256".parse()
        .expect("compile-time constant")
});

#[test]
fn noise_params_parse() {
    let _ = *NOISE_PARAMS; // validates the constant
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
