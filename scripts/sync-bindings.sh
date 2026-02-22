#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Apple settings ──────────────────────────────────────────────────
PACKAGE_DIR="$ROOT_DIR/apple/HWCoreKit"
BINDINGS_DIR="$ROOT_DIR/target/bindings/swift"

# ── Android settings ────────────────────────────────────────────────
ANDROID_LIB_DIR="$ROOT_DIR/android/lib"

# ── Flags ───────────────────────────────────────────────────────────
DO_APPLE=0
DO_ANDROID=0
DO_SYNC_BINDINGS=1
DO_BUILD_IOS_SIM_FFI=0
ANDROID_BUILD_FLAG=""
ANDROID_BUILD_MODE="debug"

find_registry_crate_dir() {
  local pattern="$1"
  local latest=""
  for d in "$HOME"/.cargo/registry/src/*/$pattern; do
    [[ -d "$d" ]] || continue
    latest="$d"
  done
  [[ -n "$latest" ]] && echo "$latest"
}

sync_android_java_support() {
  local jni_utils_dir="${JNI_UTILS_RS_DIR:-}"
  local btleplug_dir="${BTLEPLUG_RS_DIR:-}"

  if [[ -z "$jni_utils_dir" ]]; then
    jni_utils_dir="$(find_registry_crate_dir "jni-utils-*")"
  fi
  if [[ -z "$btleplug_dir" ]]; then
    btleplug_dir="$(find_registry_crate_dir "btleplug-*")"
  fi

  if [[ -z "$jni_utils_dir" || ! -d "$jni_utils_dir" ]]; then
    echo "ERROR: Could not locate jni-utils source. Set JNI_UTILS_RS_DIR to your local jni-utils-rs checkout." >&2
    exit 1
  fi
  if [[ -z "$btleplug_dir" || ! -d "$btleplug_dir" ]]; then
    echo "ERROR: Could not locate btleplug source. Set BTLEPLUG_RS_DIR to your local btleplug checkout." >&2
    exit 1
  fi

  local jni_src="$jni_utils_dir/java/src/main/java/io/github/gedgygedgy/rust"
  local btleplug_src="$btleplug_dir/src/droidplug/java/src/main/java/com/nonpolynomial/btleplug"
  local jni_dst="$ANDROID_LIB_DIR/src/main/java/io/github/gedgygedgy/rust"
  local btleplug_dst="$ANDROID_LIB_DIR/src/main/java/com/nonpolynomial/btleplug"

  if [[ ! -d "$jni_src" ]]; then
    echo "ERROR: Missing jni-utils Java sources at: $jni_src" >&2
    exit 1
  fi
  if [[ ! -d "$btleplug_src" ]]; then
    echo "ERROR: Missing btleplug Java sources at: $btleplug_src" >&2
    exit 1
  fi

  rm -rf "$jni_dst" "$btleplug_dst"
  mkdir -p "$(dirname "$jni_dst")" "$(dirname "$btleplug_dst")"
  cp -R "$jni_src" "$jni_dst"
  cp -R "$btleplug_src" "$btleplug_dst"
}

usage() {
  cat <<'EOF'
Usage: sync-bindings.sh [--apple|--android|--all] [OPTIONS]

Platform flags (at least one required):
  --apple           Sync Apple/Swift bindings (default if none specified)
  --android         Build Android .so libs + sync Kotlin bindings
  --all             Both Apple and Android

Apple options:
  --ios-sim-ffi     Also build universal iOS-simulator libhwcore.dylib
  --ios-sim-only    Build iOS-simulator lib only (skip Swift binding sync)

Android options:
  --release         Build Android native libs in release mode
EOF
}

# If no args, default to --apple
if [[ $# -eq 0 ]]; then
  DO_APPLE=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apple)
      DO_APPLE=1
      ;;
    --android)
      DO_ANDROID=1
      ;;
    --all)
      DO_APPLE=1
      DO_ANDROID=1
      ;;
    --ios-sim-ffi)
      DO_BUILD_IOS_SIM_FFI=1
      ;;
    --ios-sim-only)
      DO_SYNC_BINDINGS=0
      DO_BUILD_IOS_SIM_FFI=1
      ;;
    --release)
      ANDROID_BUILD_FLAG="--release"
      ANDROID_BUILD_MODE="release"
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

# ── Apple: sync Swift bindings ──────────────────────────────────────
if [[ "$DO_APPLE" -eq 1 ]]; then
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
      "$ROOT_DIR/target/aarch64-apple-ios-sim/debug/libhwcore.dylib" \
      "$ROOT_DIR/target/x86_64-apple-ios/debug/libhwcore.dylib" \
      -output "$ROOT_DIR/target/ios-sim/debug/libhwcore.dylib"

    echo "Built universal iOS-simulator FFI library:"
    echo "  $ROOT_DIR/target/ios-sim/debug/libhwcore.dylib"
  fi
fi

# ── Android: cross-compile + sync Kotlin bindings ──────────────────
if [[ "$DO_ANDROID" -eq 1 ]]; then
  TARGETS=(
    "arm64-v8a"
    "armeabi-v7a"
    "x86_64"
  )

  ABI_MAP_arm64_v8a="aarch64-linux-android"
  ABI_MAP_armeabi_v7a="armv7-linux-androideabi"
  ABI_MAP_x86_64="x86_64-linux-android"

  echo "==> Building hw-ffi for Android targets ($ANDROID_BUILD_MODE)..."

  cd "$ROOT_DIR"

  for abi in "${TARGETS[@]}"; do
    var_name="ABI_MAP_${abi//-/_}"
    rust_target="${!var_name}"
    echo "  -> $abi ($rust_target)"
    cargo ndk --target "$abi" --platform 28 -- build -p hw-ffi $ANDROID_BUILD_FLAG
  done

  echo "==> Copying .so files to jniLibs..."

  for abi in "${TARGETS[@]}"; do
    var_name="ABI_MAP_${abi//-/_}"
    rust_target="${!var_name}"
    src="$ROOT_DIR/target/$rust_target/$ANDROID_BUILD_MODE/libhwcore.so"
    dst="$ANDROID_LIB_DIR/src/main/jniLibs/$abi/libhwcore.so"
    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
    echo "  -> $dst"
  done

  echo "==> Syncing Android Java support sources (jni-utils + btleplug)..."
  sync_android_java_support
  echo "  -> Copied Java support into $ANDROID_LIB_DIR/src/main/java"

  echo "==> Generating Kotlin bindings..."

  mkdir -p "$ROOT_DIR/target/bindings/kotlin"
  # Ensure pkg-config can find dbus-1 (needed by btleplug host build for generate-bindings).
  # Append common distro paths only if they exist; set PKG_CONFIG_PATH manually if your
  # distro uses a different location.
  for _pkgdir in /usr/lib/aarch64-linux-gnu/pkgconfig /usr/lib/x86_64-linux-gnu/pkgconfig; do
    [[ -d "$_pkgdir" ]] && export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:+$PKG_CONFIG_PATH:}$_pkgdir"
  done
  # Use --lib with an explicit path to a cross-compiled .so because --auto only
  # searches target/{debug,release} which won't exist on cross-compile-only hosts.
  BINDGEN_LIB="$ROOT_DIR/target/aarch64-linux-android/$ANDROID_BUILD_MODE/libhwcore.so"
  cargo run -p hw-ffi --features bindings-cli --bin generate-bindings \
    -- --lib "$BINDGEN_LIB" "$ROOT_DIR/target/bindings/swift" "$ROOT_DIR/target/bindings/kotlin"

  UNIFFI_SRC="$ROOT_DIR/target/bindings/kotlin/uniffi/hwcore/hwcore.kt"
  UNIFFI_DST="$ANDROID_LIB_DIR/src/main/java/uniffi/hwcore/hwcore.kt"
  mkdir -p "$(dirname "$UNIFFI_DST")"
  cp "$UNIFFI_SRC" "$UNIFFI_DST"
  echo "  -> Bindings copied to $UNIFFI_DST"

  echo "==> Android build done!"
fi
