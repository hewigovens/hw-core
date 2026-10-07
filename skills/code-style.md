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

Use native `async fn` in traits with `#[allow(async_fn_in_trait)]` on the trait (Rust 2024 edition), as in `thp/backend.rs`. Do not use the `async-trait` proc macro for statically dispatched traits.

```rust
// good
#[allow(async_fn_in_trait)]
pub trait ThpBackend: Send {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse>;
}

// bad — unnecessary macro for a generic-only trait
#[async_trait]
pub trait ThpBackend: Send { ... }
```

Exception: traits used as `dyn` objects (e.g. `PairingController`, `ThpStorage`) need `#[async_trait]`, since native async trait methods are not object-safe.

## Interior Mutability

Use `parking_lot::Mutex` over `std::sync::Mutex` for non-async contexts. For async-aware locking, use `tokio::sync::Mutex`.

```rust
// good — synchronous state (test mocks in thp/workflow/tests.rs)
tag_requests: parking_lot::Mutex<Vec<PairingTagRequest>>,

// good — held across .await
session: tokio::sync::Mutex<Option<Session>>,
```

## Protobuf

Proto files are vendored in `crates/thp-proto/proto/`. Generated via `prost-build` + `protoc-bin-vendored` in `crates/thp-proto/build.rs`. Do not edit generated code.

## FFI

UniFFI 0.32 with derive macros. Annotate exported types and methods:

```rust
#[derive(uniffi::Object)]
pub struct BleWorkflowHandle { ... }

#[uniffi::export(async_runtime = "tokio")]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn pair_only(&self, try_to_unlock: bool) -> Result<SessionState, HWCoreError> { ... }
}
```
