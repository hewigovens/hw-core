# Development Commands

## Core Commands

```bash
just build            # cargo build --workspace
just test             # cargo test --workspace
just lint             # cargo clippy --workspace --all-targets --all-features -- -D warnings
just fmt              # cargo fmt --all
just ci               # fmt check + clippy + test (mirrors CI)
just bindings         # build hw-ffi and generate Swift/Kotlin bindings
```

## Running a Single Test

```bash
cargo test -p <crate-name> <test_name>
```

## CLI

```bash
cargo run -p hw-cli -- -vv scan                # scan for BLE devices
cargo run -p hw-cli -- -vv pair                # pair with a device
cargo run -p hw-cli -- -vv pair --force        # reset and re-pair
cargo run -p hw-cli -- -vv address --chain eth # get Ethereum address
cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{...}'
```

## Mobile / Desktop

```bash
just run-mac          # build bindings + run macOS sample app
just run-ios          # build bindings + run iOS simulator
just run-ios-device   # build bindings + run on connected iPhone
just run-android      # build + install + run on connected Android device
just android-logs     # stream filtered logcat
```

## Code Quality

```bash
just audit            # cargo audit (dependency vulnerabilities)
just scan-demo        # run BLE scan example
just workflow-demo    # run BLE handshake example
```
