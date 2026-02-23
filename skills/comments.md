# Comments

## When to Comment

Comment *why*, not *what*. Do not restate what the code does.

```rust
// bad — restates the code
// Increment the counter by one.
counter += 1;

// good — explains intent
// Retry count tracks consecutive failures; reset on success.
counter += 1;
```

## Doc Comments

Use `///` on all public types, traits, and functions in library crates. FFI-exported methods (`#[uniffi::export]`) must have doc comments since they define the API surface for iOS/Android consumers.

```rust
/// Scan for BLE devices matching the configured profile.
///
/// Returns a stream of discovered devices. The scan stops when
/// the returned `ScanHandle` is dropped.
pub fn scan(&self) -> ScanHandle { ... }
```

## Safety and Invariant Comments

When an `unwrap()` or `expect()` is provably safe, add a comment explaining why:

```rust
// SAFETY: & 0xFF guarantees the value is in [0, 255], always valid for u8.
let byte = (value & BigInt::from(0xffu8)).to_u8().unwrap();
```

## TODO Format

Use `TODO(<context>):` with enough context to act on later:

```rust
// TODO(p1): Replace string-matching with structured error variants.
// TODO(thp-v2): Remove legacy channel creation path after protocol upgrade.
```
