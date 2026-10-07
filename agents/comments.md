# Comments

- Comments and doc comments are opt-in. When needed, keep them to one line.
- Comment *why* (intent, invariants, safety), never restate *what* the code does.
- Public APIs do not need blanket `///` coverage; add one only when it improves a consumer-facing surface such as CLI help or FFI bindings.
- When an `unwrap()`/`expect()` is provably safe, say why in a one-line `// SAFETY:` comment.
- Write TODOs as `TODO(<context>): <actionable note>`.
