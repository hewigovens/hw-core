#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PACKAGE_DIR="$ROOT_DIR/apple/HWCoreKit"
BINDINGS_DIR="$ROOT_DIR/target/bindings/swift"

mkdir -p "$PACKAGE_DIR/Sources/HWCoreFFI"
mkdir -p "$PACKAGE_DIR/Sources/libhwcore"

cp "$BINDINGS_DIR/HWCoreFFI.swift" "$PACKAGE_DIR/Sources/HWCoreFFI/HWCoreFFI.swift"
cp "$BINDINGS_DIR/libhwcore.h" "$PACKAGE_DIR/Sources/libhwcore/libhwcore.h"
cp "$BINDINGS_DIR/libhwcore.modulemap" "$PACKAGE_DIR/Sources/libhwcore/module.modulemap"

echo "Synced UniFFI Swift bindings into apple/HWCoreKit"
