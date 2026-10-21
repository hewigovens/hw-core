#!/usr/bin/env bash
# Builds target/xcframework/HWCore.xcframework (iOS device, iOS simulator, macOS) from release
# builds of hw-ffi, plus the matching Swift bindings in target/xcframework/swift.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT_DIR/target/xcframework"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-16.0}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-13.0}"
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

cd "$ROOT_DIR"
rustup target add "${IOS_TARGETS[@]}" "${MACOS_TARGETS[@]}"
for target in "${IOS_TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" cargo build -p hw-ffi --release --target "$target"
done
for target in "${MACOS_TARGETS[@]}"; do
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" cargo build -p hw-ffi --release --target "$target"
done

lib() { echo "$ROOT_DIR/target/$1/release/libhwcore.a"; }
rm -rf "$OUT"
mkdir -p "$OUT/ios-simulator" "$OUT/macos" "$OUT/headers" "$OUT/swift"
lipo -create "$(lib aarch64-apple-ios-sim)" "$(lib x86_64-apple-ios)" -output "$OUT/ios-simulator/libhwcore.a"
lipo -create "$(lib aarch64-apple-darwin)" "$(lib x86_64-apple-darwin)" -output "$OUT/macos/libhwcore.a"

cargo run -q -p hw-ffi --features bindings-cli --bin generate-bindings -- \
  --lib "$(lib aarch64-apple-darwin)" "$OUT/bindings-swift" "$OUT/bindings-kotlin"
cp "$OUT/bindings-swift/libhwcore.h" "$OUT/headers/"
cp "$OUT/bindings-swift/libhwcore.modulemap" "$OUT/headers/module.modulemap"
cp "$OUT/bindings-swift/HWCoreFFI.swift" "$OUT/swift/"
rm -rf "$OUT/bindings-swift" "$OUT/bindings-kotlin"

xcodebuild -create-xcframework \
  -library "$(lib aarch64-apple-ios)" -headers "$OUT/headers" \
  -library "$OUT/ios-simulator/libhwcore.a" -headers "$OUT/headers" \
  -library "$OUT/macos/libhwcore.a" -headers "$OUT/headers" \
  -output "$OUT/HWCore.xcframework"

echo "Built $OUT/HWCore.xcframework and $OUT/swift/HWCoreFFI.swift"
