# Code Style

## Async Runtime

Use Tokio. Multi-thread runtime in CLI; current-thread acceptable in tests.

```rust
// good — CLI main
#[tokio::main]
async fn main() -> anyhow::Result<()> { ... }

// good — test
#[tokio::test]
async fn my_test() { ... }
```

## Module Organization

Split large files by responsibility. Keep the struct definition and trait impl in separate files when the impl is large.

```
// good — trezor-connect structure
src/
  ble.rs                 // BleBackend struct + helpers
  ble/
    backend_impl.rs      // ThpBackend impl for BleBackend
    tests.rs             // unit tests
```

Do not put everything in one file. If a file exceeds ~500 lines, consider splitting.

## Trait Design

Use `#[allow(async_fn_in_trait)]` for async traits (Rust 2024 edition). Do not use the `async-trait` proc macro for new code.

```rust
// good
pub trait ThpBackend {
    #[allow(async_fn_in_trait)]
    async fn create_channel(&mut self) -> Result<(), BackendError>;
}

// bad — unnecessary macro
#[async_trait]
pub trait ThpBackend {
    async fn create_channel(&mut self) -> Result<(), BackendError>;
}
```

## Interior Mutability

Use `parking_lot::Mutex` over `std::sync::Mutex` for non-async contexts. For async-aware locking, use `tokio::sync::Mutex`.

```rust
// good — synchronous state
state: parking_lot::Mutex<ThpState>,

// good — held across .await
session: tokio::sync::Mutex<Option<Session>>,
```

## Protobuf

Proto files are vendored in `thp-proto/`. Generated via `prost-build` + `protoc-bin-vendored` in `thp-proto/build.rs`. Do not edit generated code.

## FFI

UniFFI 0.31 with derive macros. Annotate exported types and methods:

```rust
#[derive(uniffi::Object)]
pub struct BleWorkflowHandle { ... }

#[uniffi::export]
impl BleWorkflowHandle {
    pub async fn pair(&self) -> Result<(), HWCoreError> { ... }
}
```
