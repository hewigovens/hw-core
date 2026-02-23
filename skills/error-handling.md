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
        BackendError::Device(msg) => msg.contains("error code 5"),
        _ => false,
    }
}

// good — structured variant
enum BackendError {
    DeviceBusy,
    TransportTimeout,
    DeviceError { code: u32, message: String },
    // ...
}

fn is_retryable(err: &BackendError) -> bool {
    matches!(err, BackendError::DeviceBusy | BackendError::TransportTimeout)
}
```

## Error Type Design

Use `#[from]` for automatic conversion from inner errors. Add context with `.map_err()`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("workflow error: {0}")]
    Workflow(#[from] ThpWorkflowError),

    #[error("BLE transport: {0}")]
    Transport(#[from] BleError),

    #[error("{0}")]
    Other(String),
}
```
