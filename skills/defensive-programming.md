# Defensive Programming

## Use the Type System to Prevent Bugs

Prefer compile-time guarantees over runtime checks.

```rust
// bad — wrong key length fails at runtime
fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AeadError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| AeadError)?
    // ...
}

// good — wrong key length is a compile error
fn encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = Aes256Gcm::new(key.into());
    // ...
}
```

## Use Enums for Mutually Exclusive States

Do not use a flat struct with optional fields when only one variant applies.

```rust
// bad — Solana request carries dummy Ethereum fields
struct SignTxRequest {
    nonce: Vec<u8>,      // unused for Solana
    gas_limit: Vec<u8>,  // unused for Solana
    sol_data: Vec<u8>,   // unused for Ethereum
}

// good — each chain is its own variant
enum SignTxPayload {
    Ethereum(EthSignTx),
    Solana(SolanaSignTx),
    Bitcoin(BtcSignTx),
}
```

## Exhaustive Matching

Always match all enum variants explicitly. Do not use wildcard `_` for enums that may grow.

```rust
// bad — new variant silently falls through
match chain {
    Chain::Ethereum => { ... }
    _ => return Err(UnsupportedChain),
}

// good — compiler catches new variants
match chain {
    Chain::Ethereum => { ... }
    Chain::Bitcoin => { ... }
    Chain::Solana => { ... }
}
```

## Atomic File Operations

When writing persistent state, use write-to-temp-then-rename to prevent corruption:

```rust
// good — atomic write (already used in FileStorage)
let tmp = path.with_extension("tmp");
fs::write(&tmp, data)?;
fs::rename(&tmp, &path)?;
```

## Constant-Time Comparisons for Secrets

Use `subtle::ConstantTimeEq` when comparing cryptographic keys or secrets:

```rust
// bad — timing side channel
if key == &[0u8; 32] { ... }

// good — constant-time
use subtle::ConstantTimeEq;
if key.ct_eq(&[0u8; 32]).into() { ... }
```

## Drop for Resource Cleanup

Implement `Drop` on types that own background tasks or system resources:

```rust
// good — BleLink shuts down notification listener on drop
impl Drop for BleLink {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
    }
}
```
