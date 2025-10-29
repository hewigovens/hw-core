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

scan-demo:
    cargo run -p ble-transport --features trezor-safe7,backend-btleplug --example scan_trezor

workflow-demo:
    cargo run -p trezor-connect --features ble --example ble_handshake
