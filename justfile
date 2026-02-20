set dotenv-load := false
set positional-arguments := false
set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

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
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p hw-ffi
    mkdir -p target/bindings/swift target/bindings/kotlin
    cargo run -p hw-ffi --features bindings-cli --bin generate-bindings -- --auto target/bindings/swift target/bindings/kotlin
    if [[ "$(uname -s)" == "Darwin" ]]; then
        ./apple/HWCoreKit/Scripts/sync-bindings.sh --ios-sim-ffi
    else
        ./apple/HWCoreKit/Scripts/sync-bindings.sh
    fi

_ios-sim-device-id:
    #!/usr/bin/env bash
    set -euo pipefail
    SIM_DEVICE_ID="$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/{print $2; exit}')"
    if [[ -z "$SIM_DEVICE_ID" ]]; then
        echo "No available iPhone simulator found." >&2
        exit 1
    fi
    echo "$SIM_DEVICE_ID"

sample:
    just bindings
    swift run --package-path apple/HWCoreKitSampleApp

install-xcbeautify:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v xcbeautify >/dev/null 2>&1; then
        xcbeautify --version
        exit 0
    fi
    if ! command -v brew >/dev/null 2>&1; then
        echo "xcbeautify is not installed and Homebrew is unavailable. Install xcbeautify manually." >&2
        exit 1
    fi
    brew install xcbeautify

run-mac:
    just sample

build-ios:
    just install-xcbeautify
    just bindings
    xcodegen generate --spec apple/HWCoreKitSampleApp/project-ios.yml
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj -scheme HWCoreKitSampleAppiOS -destination 'generic/platform=iOS Simulator' build | xcbeautify

build-ios-ui:
    just install-xcbeautify
    just bindings
    xcodegen generate --spec apple/HWCoreKitSampleApp/project-ios.yml
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj -scheme HWCoreKitSampleAppiOS -destination 'generic/platform=iOS Simulator' build-for-testing | xcbeautify

test-ios-ui:
    #!/usr/bin/env bash
    set -euo pipefail
    just install-xcbeautify
    just build-ios-ui
    SIM_DEVICE_ID="$(just --quiet _ios-sim-device-id)"
    xcrun simctl boot "$SIM_DEVICE_ID" >/dev/null 2>&1 || true
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj -scheme HWCoreKitSampleAppiOS -destination "id=$SIM_DEVICE_ID" test-without-building | xcbeautify

run-ios:
    #!/usr/bin/env bash
    set -euo pipefail
    just install-xcbeautify
    just bindings
    xcodegen generate --spec apple/HWCoreKitSampleApp/project-ios.yml
    SIM_DEVICE_ID="$(just --quiet _ios-sim-device-id)"
    xcrun simctl boot "$SIM_DEVICE_ID" >/dev/null 2>&1 || true
    open -a Simulator --args -CurrentDeviceUDID "$SIM_DEVICE_ID"
    xcrun simctl bootstatus "$SIM_DEVICE_ID" -b
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppiOS.xcodeproj -scheme HWCoreKitSampleAppiOS -destination "id=$SIM_DEVICE_ID" -derivedDataPath target/DerivedData/HWCoreKitSampleAppiOS build | xcbeautify
    xcrun simctl install "$SIM_DEVICE_ID" target/DerivedData/HWCoreKitSampleAppiOS/Build/Products/Debug-iphonesimulator/HWCoreKitSampleAppiOS.app
    xcrun simctl launch "$SIM_DEVICE_ID" dev.hewig.hwcorekit.sampleiosapp
    open -a Simulator

test-mac-ui:
    just install-xcbeautify
    just build-mac-ui
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppMac.xcodeproj -scheme HWCoreKitSampleAppMac -destination 'platform=macOS' test-without-building | xcbeautify

build-mac-ui:
    just install-xcbeautify
    just bindings
    xcodegen generate --spec apple/HWCoreKitSampleApp/project-mac.yml
    xcodebuild -project apple/HWCoreKitSampleApp/HWCoreKitSampleAppMac.xcodeproj -scheme HWCoreKitSampleAppMac -destination 'platform=macOS' build-for-testing | xcbeautify

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

cli-address-eth:
    cargo run -p hw-cli -- -vv address --chain eth --include-public-key

cli-sign-eth:
    cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x0"}'
