# Contributing to hw-core

Thanks for contributing.

## Local setup

- Rust stable toolchain (2024 edition support)
- `just` (optional, but recommended)
- For Linux BLE builds: `libdbus-1-dev` and `pkg-config`

## Development loop

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Or use `just`:

```bash
just fmt
just lint
just test
just build
just ci
```

## Useful hw-cli commands

```bash
just cli-scan
just cli-pair
just cli-address-eth
just cli-sign-eth
```

Direct examples:

```bash
cargo run -p hw-cli -- -vv pair
cargo run -p hw-cli -- -vv address --chain eth --include-public-key
cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x0"}'
```

Notes:

- Pairing state is stored at `~/.hw-core/thp-host.json`
- Use `pair --force` to reset credential flow

## FFI bindings

Generate Swift/Kotlin bindings:

```bash
just bindings
```

Manual generation:

```bash
cargo run -p hw-ffi --features bindings-cli --bin generate-bindings --auto target/bindings/swift target/bindings/kotlin
```

## Documentation map

- Project roadmap: `docs/roadmap.md`
- Consolidated execution plan: `docs/plan.md`
- Security policy: `SECURITY.md`

## Pull request checklist

- Keep changes scoped and cohesive
- Add or update tests for behavior changes
- Run `just ci` locally before opening PR
- Update docs when public behavior or workflow changes
