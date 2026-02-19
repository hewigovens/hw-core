#!/usr/bin/env bash
#
# Cross-compile hw-ffi for Android targets and copy .so files into the
# lib module's jniLibs directory.
#
# Prerequisites:
#   - Android NDK installed (set ANDROID_NDK_HOME)
#   - Rust targets installed:
#       rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   - cargo-ndk installed:
#       cargo install cargo-ndk
#
# Usage:
#   ./android/scripts/build-rust.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIB_DIR="$SCRIPT_DIR/../lib"

BUILD_FLAG=""
BUILD_MODE="debug"
if [[ "${1:-}" == "--release" ]]; then
    BUILD_FLAG="--release"
    BUILD_MODE="release"
fi

TARGETS=(
    "arm64-v8a"
    "armeabi-v7a"
    "x86_64"
)

ABI_MAP_arm64_v8a="aarch64-linux-android"
ABI_MAP_armeabi_v7a="armv7-linux-androideabi"
ABI_MAP_x86_64="x86_64-linux-android"

echo "==> Building hw-ffi for Android targets ($BUILD_MODE)..."

cd "$PROJECT_ROOT"

for abi in "${TARGETS[@]}"; do
    var_name="ABI_MAP_${abi//-/_}"
    rust_target="${!var_name}"
    echo "  -> $abi ($rust_target)"
    cargo ndk --target "$abi" --platform 28 -- build -p hw-ffi $BUILD_FLAG
done

echo "==> Copying .so files to jniLibs..."

for abi in "${TARGETS[@]}"; do
    var_name="ABI_MAP_${abi//-/_}"
    rust_target="${!var_name}"
    src="$PROJECT_ROOT/target/$rust_target/$BUILD_MODE/libhw_ffi.so"
    dst="$LIB_DIR/src/main/jniLibs/$abi/libhw_ffi.so"
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    echo "  -> $dst"
done

echo "==> Generating Kotlin bindings..."

mkdir -p "$PROJECT_ROOT/target/bindings/kotlin"
cargo run -p hw-ffi --features bindings-cli --bin generate-bindings \
    -- --auto "$PROJECT_ROOT/target/bindings/swift" "$PROJECT_ROOT/target/bindings/kotlin"

UNIFFI_SRC="$PROJECT_ROOT/target/bindings/kotlin/uniffi/hw_ffi/hw_ffi.kt"
UNIFFI_DST="$LIB_DIR/src/main/java/uniffi/hw_ffi/hw_ffi.kt"
mkdir -p "$(dirname "$UNIFFI_DST")"
cp "$UNIFFI_SRC" "$UNIFFI_DST"
echo "  -> Bindings copied to $UNIFFI_DST"

echo "==> Done!"
