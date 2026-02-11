set dotenv-load := false
set positional-arguments := false

default:
    @just --list

fmt:
    cargo fmt --all

format:
    just fmt

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

audit:
    cargo audit

build:
    cargo build --workspace

test:
    cargo test --workspace

ci:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --all-features -- -D warnings
    cargo test --workspace

bindings:
    cargo build -p hw-ffi
    mkdir -p target/bindings/swift target/bindings/kotlin
    cargo run -p hw-ffi --features bindings-cli --bin generate-bindings -- --auto target/bindings/swift target/bindings/kotlin
    ./apple/HWCoreKit/Scripts/sync-bindings.sh

hwcorekit-sample:
    just bindings
    swift run --package-path apple/HWCoreKitSampleApp

scan-demo:
    cargo run -p ble-transport --features trezor-safe7,backend-btleplug --example scan_trezor

workflow-demo:
    cargo run -p trezor-connect --features ble --example ble_handshake

cli-help:
    cargo run -p hw-cli -- -vv --help

cli-scan:
    cargo run -p hw-cli -- -vv scan

cli-pair:
    cargo run -p hw-cli -- -vv pair

cli-pair-interactive:
    cargo run -p hw-cli -- -vv pair --interactive

cli-address-eth:
    cargo run -p hw-cli -- -vv address --chain eth --include-public-key

cli-sign-eth:
    cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x0"}'
