#!/usr/bin/env bash
# Run emulator BLE integration tests with Apple container (macOS) or Docker (Linux).
# Requires: the selected runtime and curl (for the pinned emulator fixture).
#
# Usage:
#   ./scripts/test-emu.sh           # build + test
#   ./scripts/test-emu.sh --shell   # drop into a shell for debugging
#   CONTAINER_RUNTIME=docker ./scripts/test-emu.sh

set -euo pipefail
cd "$(dirname "$0")/.."

case "${1:-}" in
    ""|--shell) ;;
    -h|--help)
        echo "Usage: $0 [--shell]"
        echo "CONTAINER_RUNTIME=container|docker (default: container on macOS, docker elsewhere)"
        echo "EMU_IMAGE_NAME=hw-core-emu-test EMU_CPUS=4 EMU_MEMORY=4G"
        exit 0
        ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [--shell]" >&2
    exit 2
fi

if [ "$(uname -s)" = Darwin ]; then
    DEFAULT_RUNTIME=container
else
    DEFAULT_RUNTIME=docker
fi
RUNTIME="${CONTAINER_RUNTIME:-$DEFAULT_RUNTIME}"
case "$RUNTIME" in
    container|docker) ;;
    *) echo "Unsupported CONTAINER_RUNTIME: $RUNTIME (use container or docker)" >&2; exit 2 ;;
esac
if ! command -v "$RUNTIME" >/dev/null; then
    echo "Required runtime not found: $RUNTIME (see CONTRIBUTING.md)" >&2
    exit 1
fi

EMU_BINARY="tests/fixtures/trezor-emu-core-T3W1"
EMU_FIXTURES_TAG="emu-fixtures-v2.12.5"
EMU_TAG_FILE="$EMU_BINARY.tag"
IMAGE_NAME="${EMU_IMAGE_NAME:-hw-core-emu-test}"
PLATFORM="linux/amd64"
CPUS="${EMU_CPUS:-4}"
MEMORY="${EMU_MEMORY:-4G}"

# Keep the original fixture intact if a download fails.
if [ ! -f "$EMU_BINARY" ] || [ "$(cat "$EMU_TAG_FILE" 2>/dev/null)" != "$EMU_FIXTURES_TAG" ]; then
    echo "==> Downloading T3W1 emulator binary ($EMU_FIXTURES_TAG)..."
    DOWNLOAD="$(mktemp "$EMU_BINARY.XXXXXX")"
    trap 'rm -f "$DOWNLOAD"' EXIT
    curl --fail --location --retry 3 \
        "https://github.com/hewigovens/hw-core/releases/download/$EMU_FIXTURES_TAG/trezor-emu-core-T3W1" \
        --output "$DOWNLOAD"
    chmod +x "$DOWNLOAD"
    mv "$DOWNLOAD" "$EMU_BINARY"
    echo "$EMU_FIXTURES_TAG" > "$EMU_TAG_FILE"
    trap - EXIT
fi

BUILD_ARGS=(--platform "$PLATFORM" --build-arg "BUILD_JOBS=$CPUS")
if [ "$RUNTIME" = container ]; then
    BUILD_ARGS+=(--cpus "$CPUS" --memory "$MEMORY")
fi

echo "==> Building emulator image with $RUNTIME ($PLATFORM)..."
"$RUNTIME" build "${BUILD_ARGS[@]}" -f Containerfile.emu-test -t "$IMAGE_NAME" .

RUN_ARGS=(--platform "$PLATFORM" --cpus "$CPUS" --memory "$MEMORY" --rm)
if [ "${1:-}" = "--shell" ]; then
    echo "==> Starting interactive shell..."
    exec "$RUNTIME" run "${RUN_ARGS[@]}" -it "$IMAGE_NAME" /bin/bash
else
    echo "==> Running emulator integration tests..."
    exec "$RUNTIME" run "${RUN_ARGS[@]}" "$IMAGE_NAME"
fi
