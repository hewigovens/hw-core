#!/usr/bin/env bash
# Builds target/xcframework/HWCore.xcframework (iOS device, iOS simulator, macOS) from hw-ffi,
# plus the matching Swift bindings. Release by default; --debug for the faster local dev loop.
set -euo pipefail

# Cargo profile and its target/<triple>/<dir> output folder.
CARGO_PROFILE=release
PROFILE=release
if [[ "${1:-}" == "--debug" ]]; then
  CARGO_PROFILE=dev
  PROFILE=debug
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT_DIR/target/xcframework"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-16.0}"
MACOS_DEPLOYMENT_TARGET="${MACOS_DEPLOYMENT_TARGET:-13.0}"
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
MACOS_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

cd "$ROOT_DIR"
rustup target add "${IOS_TARGETS[@]}" "${MACOS_TARGETS[@]}"
for target in "${IOS_TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET" cargo build -p hw-ffi --profile "$CARGO_PROFILE" --target "$target"
done
for target in "${MACOS_TARGETS[@]}"; do
  MACOSX_DEPLOYMENT_TARGET="$MACOS_DEPLOYMENT_TARGET" cargo build -p hw-ffi --profile "$CARGO_PROFILE" --target "$target"
done

lib() { echo "$ROOT_DIR/target/$1/$PROFILE/libhwcore.a"; }
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

echo "Built $OUT/HWCore.xcframework ($PROFILE) and $OUT/swift/HWCoreFFI.swift"

# Stage a portable package and refresh the in-repo package from the same build.
PACKAGE="$OUT/HWCoreKit"
mkdir -p "$PACKAGE/Sources/HWCoreFFI"
cp "$ROOT_DIR/apple/HWCoreKit/Package.swift" "$PACKAGE/"
cp "$ROOT_DIR/apple/HWCoreKit/README.md" "$PACKAGE/"
cp -R "$ROOT_DIR/apple/HWCoreKit/Sources/HWCoreKit" "$PACKAGE/Sources/"
cp -R "$ROOT_DIR/apple/HWCoreKit/Tests" "$PACKAGE/"
cp -R "$OUT/HWCore.xcframework" "$PACKAGE/"
cp "$OUT/swift/HWCoreFFI.swift" "$PACKAGE/Sources/HWCoreFFI/"
rm -rf "$ROOT_DIR/apple/HWCoreKit/HWCore.xcframework"
cp -R "$PACKAGE/HWCore.xcframework" "$ROOT_DIR/apple/HWCoreKit/"
mkdir -p "$ROOT_DIR/apple/HWCoreKit/Sources/HWCoreFFI"
cp "$PACKAGE/Sources/HWCoreFFI/HWCoreFFI.swift" "$ROOT_DIR/apple/HWCoreKit/Sources/HWCoreFFI/"
echo "Packaged $PACKAGE (copy this directory into your app repository)"
