#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/apple/HWCoreKit"
BINDINGS_DIR="$ROOT_DIR/target/bindings/swift"
DO_SYNC_BINDINGS=1
DO_BUILD_IOS_SIM_FFI=0

usage() {
  cat <<'EOF'
Usage: sync-bindings.sh [--ios-sim-ffi|--ios-sim-only]

Options:
  --ios-sim-ffi   Build universal iOS-simulator libhw_ffi.dylib in addition to syncing bindings.
  --ios-sim-only  Build universal iOS-simulator libhw_ffi.dylib without syncing bindings.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ios-sim-ffi)
      DO_BUILD_IOS_SIM_FFI=1
      ;;
    --ios-sim-only)
      DO_SYNC_BINDINGS=0
      DO_BUILD_IOS_SIM_FFI=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ "$DO_SYNC_BINDINGS" -eq 1 ]]; then
  mkdir -p "$PACKAGE_DIR/Sources/HWCoreFFI"
  mkdir -p "$PACKAGE_DIR/Sources/libhwcore"

  cp "$BINDINGS_DIR/HWCoreFFI.swift" "$PACKAGE_DIR/Sources/HWCoreFFI/HWCoreFFI.swift"
  cp "$BINDINGS_DIR/libhwcore.h" "$PACKAGE_DIR/Sources/libhwcore/libhwcore.h"
  cp "$BINDINGS_DIR/libhwcore.modulemap" "$PACKAGE_DIR/Sources/libhwcore/module.modulemap"

  echo "Synced UniFFI Swift bindings into apple/HWCoreKit"
fi

if [[ "$DO_BUILD_IOS_SIM_FFI" -eq 1 ]]; then
  rustup target add aarch64-apple-ios-sim x86_64-apple-ios

  cargo build -p hw-ffi --target aarch64-apple-ios-sim
  cargo build -p hw-ffi --target x86_64-apple-ios

  mkdir -p "$ROOT_DIR/target/ios-sim/debug"
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-ios-sim/debug/libhw_ffi.dylib" \
    "$ROOT_DIR/target/x86_64-apple-ios/debug/libhw_ffi.dylib" \
    -output "$ROOT_DIR/target/ios-sim/debug/libhw_ffi.dylib"
  lipo -create \
    "$ROOT_DIR/target/aarch64-apple-ios-sim/debug/libhw_ffi.a" \
    "$ROOT_DIR/target/x86_64-apple-ios/debug/libhw_ffi.a" \
    -output "$ROOT_DIR/target/ios-sim/debug/libhw_ffi.a"

  echo "Built universal iOS-simulator FFI library:"
  echo "  $ROOT_DIR/target/ios-sim/debug/libhw_ffi.dylib"
  echo "  $ROOT_DIR/target/ios-sim/debug/libhw_ffi.a"
fi
