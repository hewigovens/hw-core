#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/apple/HWCoreKit"
BINDINGS_DIR="$ROOT_DIR/target/bindings/swift"

mkdir -p "$PACKAGE_DIR/Sources/HWCoreKitBindings"
mkdir -p "$PACKAGE_DIR/Sources/hw_ffiFFI"

cp "$BINDINGS_DIR/hw_ffi.swift" "$PACKAGE_DIR/Sources/HWCoreKitBindings/hw_ffi.swift"
cp "$BINDINGS_DIR/hw_ffiFFI.h" "$PACKAGE_DIR/Sources/hw_ffiFFI/hw_ffiFFI.h"
cp "$BINDINGS_DIR/hw_ffiFFI.modulemap" "$PACKAGE_DIR/Sources/hw_ffiFFI/module.modulemap"

echo "Synced UniFFI Swift bindings into apple/HWCoreKit"
