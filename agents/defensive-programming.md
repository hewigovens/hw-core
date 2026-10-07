# Defensive Programming

- **Types over runtime checks.** Encode invariants in types, e.g. take `&[u8; 32]` for keys instead of `&[u8]` plus a length check.
- **Enums for mutually exclusive states.** Model per-chain or per-phase data as enum variants, not one struct with optional fields that only some cases use.
- **Exhaustive matching.** Match every variant of enums that may grow (`Chain`, `BackendError`, ...); no `_` catch-all, so new variants fail to compile until handled.
- **Atomic file writes.** Persist state by writing a temp file and renaming it over the target (as `FileStorage` does via `platform::atomic_write`).
- **Constant-time secret comparison.** Compare keys, tags and secrets in constant time (e.g. `subtle::ConstantTimeEq`), never with `==`.
- **Drop cleans up.** Types that own background tasks or OS resources implement `Drop` (e.g. `BleLink` aborts its notification task).
