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
just cli-help
just cli-sign-message-eth
```

Direct examples:

```bash
cargo run -p hw-cli -- -vv pair
cargo run -p hw-cli -- -vv address --chain eth --include-public-key
cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x0"}'
cargo run -p hw-cli -- -vv sign-message eth --message "hello"
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
cargo run -p hw-ffi --features bindings-cli --bin generate-bindings -- --auto target/bindings/swift target/bindings/kotlin
```

## Emulator integration tests

CI runs the T3W1 emulator to test the full BLE→THP stack end-to-end.
These tests are `#[ignore]`d and only run when the harness env vars are set.

### Running locally

The easiest path on any host is Docker (`./scripts/test-emu-docker.sh`), which mirrors CI.
Natively, on Debian trixie or another distro that ships SDL3:

```bash
# 1. Install system deps
sudo apt-get install -y libdbus-1-dev pkg-config dbus libsdl3-0 libsdl3-image0 libjpeg62-turbo patchelf

# 2. Install Python deps in a venv, including the TROPIC01 model (ts-tvl) required by core v2.12+
python3 -m venv .venv && . .venv/bin/activate
pip install trezor dbus-fast click typing-extensions \
  "git+https://github.com/tropicsquare/ts-tvl@0e50063160a608d6375cd87f3afbc6f1b7726b1b"

# 3. Download or build the emulator binary (see below)
# Place it at tests/fixtures/trezor-emu-core-T3W1

# 4. Run the tests
export TREZOR_EMU_BINARY="$PWD/tests/fixtures/trezor-emu-core-T3W1"
export BRIDGE_DIR="$PWD/tests/fixtures"
export TROPIC_MODEL_CONFIG="$PWD/tests/fixtures/tropic_model/config.yml"
cargo test -p hw-cli --test emu_ble -- --ignored --nocapture --test-threads=1
cargo test -p hw-ffi --test emu_ble -- --ignored --nocapture --test-threads=1
```

The harness starts `model_server` when `TROPIC_MODEL_CONFIG` is set.

### Building the emulator binary

The T3W1 emulator must be built from [trezor-firmware](https://github.com/trezor/trezor-firmware).
CI downloads it from the `emu-fixtures-v2.12.5` GitHub release (built from `core/v2.12.5`).

To rebuild (requires Nix; on Apple Silicon run inside a `nixos/nix` container with `--platform linux/amd64`):

```bash
# Use a short checkout path: mpy-cross fails with "name too long" on deep paths.
git clone --recursive --branch core/v2.12.5 https://github.com/trezor/trezor-firmware /fw
cd /fw
TREZOR_MODEL=T3W1 PYOPT=0 nix-shell --run "uv run make -C core build_unix_frozen"
# Output: core/build-xtask/artifacts/T3W1/firmware-emu
```

The binary must match the CI runner architecture (Linux x86_64).
When bumping firmware, also update `tests/fixtures/tropic_model/config.yml` from
`tests/tropic_model/config.yml` and the ts-tvl commit (`vendor/ts-tvl` submodule) at the same tag.

Upload a new binary to a new tag, then point `EMU_FIXTURES_TAG` in
`.github/workflows/emu-integration.yml` and `scripts/test-emu-docker.sh` at it:

```bash
gh release create emu-fixtures-vX.Y.Z --repo hewigovens/hw-core --title "Emulator fixtures (core vX.Y.Z)" \
  core/build-xtask/artifacts/T3W1/firmware-emu#trezor-emu-core-T3W1
```

### Updating the bluez-emu-bridge

The vendored bridge at `tests/fixtures/bluez_emu_bridge/` comes from
`trezor-firmware/core/tools/`. To update, copy the files from a newer commit
and update the SHA in `tests/fixtures/README.md`.

## Documentation map

- Project roadmap: `docs/roadmap.md`
- Consolidated execution plan: `docs/plan.md`
- Canonical smoke matrix: `docs/smoke-matrix.md`
- Release checklist: `docs/release-checklist.md`
- Security policy: `SECURITY.md`

## Pull request checklist

- Keep changes scoped and cohesive
- Add or update tests for behavior changes
- Run `just ci` locally before opening PR
- Update docs when public behavior or workflow changes
