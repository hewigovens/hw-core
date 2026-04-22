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

Comments and doc comments are optional by default. When they add value, keep them to a single line. Public APIs do not need blanket `///` coverage; add a short doc comment only when it materially improves the consumer-facing surface (for example CLI help or FFI bindings).

```rust
/// Scan for BLE devices matching the configured profile.
pub fn scan(&self) -> ScanHandle { ... }
```

## Safety and Invariant Comments

When an `unwrap()` or `expect()` is provably safe, add a one-line comment explaining why:

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
