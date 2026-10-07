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
just build-android    # sync bindings + native libs for Android (scripts/sync-bindings.sh --android)
just build-ios        # build bindings + xcodegen + build iOS sample app for simulator
just generate-apple-projects  # xcodegen iOS + macOS sample app projects
just smoke-ios-ui     # build-for-testing + run iOS UI tests on a simulator (needs generated project)
just test-mac-ui      # build bindings + run macOS sample app UI tests
```

CI (`ios-ci.yml`) runs `just bindings`, `just generate-apple-projects`, then `just smoke-ios-ui`; `android-ci.yml` runs `just build-android`.

Apple sample app debugging:

- Process names (for `log stream --predicate 'process == "..."'`): `HWCoreKitSampleAppiOS` on iOS, `HWCoreKitSampleApp` on macOS; the macOS scheme is `HWCoreKitSampleAppMac`.
- UI controls use `action.*` accessibility identifiers (`action.scan`, `action.pair_only`, `action.connect`, `action.address`, ...) for UI tests and simulator automation.

## Code Quality

```bash
just audit            # cargo audit (dependency vulnerabilities)
just scan-demo        # run BLE scan example
just workflow-demo    # run BLE handshake example
```
