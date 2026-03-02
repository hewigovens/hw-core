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

## Emulator integration tests

CI runs the T3W1 emulator to test the full BLE→THP stack end-to-end.
These tests are `#[ignore]`d and only run when the harness env vars are set.

### Running locally (Linux only)

```bash
# 1. Install system deps
sudo apt-get install -y libdbus-1-dev pkg-config dbus libsdl2-dev libsdl2-image-dev

# 2. Install Python deps
pip install trezor dbus-fast click typing-extensions

# 3. Download or build the emulator binary (see below)
# Place it at tests/fixtures/trezor-emu-core-T3W1

# 4. Run the tests
TREZOR_EMU_BINARY=./tests/fixtures/trezor-emu-core-T3W1 \
BRIDGE_DIR=./tests/fixtures \
  cargo test -p hw-cli --test emu_ble -- --ignored --nocapture
```

### Building the emulator binary

The T3W1 emulator must be built from [trezor-firmware](https://github.com/trezor/trezor-firmware).
CI downloads it from the `emu-fixtures` GitHub release.

To rebuild (requires Nix):

```bash
git clone --recursive https://github.com/trezor/trezor-firmware
cd trezor-firmware
TREZOR_MODEL=T3W1 PYOPT=0 nix-shell --run "UV_PYTHON=3.13 uv run make -C core build_unix_frozen"
# Output: core/build/unix/trezor-emu-core
```

The binary must match the CI runner architecture (Linux x86_64 for `ubuntu-latest`).
On Apple Silicon, build inside Docker with `--platform linux/amd64`.

Upload a new binary:

```bash
gh release upload emu-fixtures core/build/unix/trezor-emu-core#trezor-emu-core-T3W1 \
  --repo hewigovens/hw-core --clobber
```

### Updating the bluez-emu-bridge

The vendored bridge at `tests/fixtures/bluez_emu_bridge/` comes from
`trezor-firmware/core/tools/`. To update, copy the files from a newer commit
and update the SHA in `tests/fixtures/README.md`.

## Documentation map

- Project roadmap: `docs/roadmap.md`
- Consolidated execution plan: `docs/plan.md`
- Security policy: `SECURITY.md`

## Pull request checklist

- Keep changes scoped and cohesive
- Add or update tests for behavior changes
- Run `just ci` locally before opening PR
- Update docs when public behavior or workflow changes
