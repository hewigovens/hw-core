#!/usr/bin/env bash
# Run emulator BLE integration tests in Docker.
# Requires: Docker, gh CLI (for downloading the emulator binary).
#
# Usage:
#   ./scripts/test-emu-docker.sh          # build + test
#   ./scripts/test-emu-docker.sh --shell   # drop into a shell for debugging

set -euo pipefail
cd "$(dirname "$0")/.."

EMU_BINARY="tests/fixtures/trezor-emu-core-T3W1"
EMU_FIXTURES_TAG="emu-fixtures-v2.12.5"
EMU_TAG_FILE="$EMU_BINARY.tag"
IMAGE_NAME="hw-core-emu-test"
PLATFORM="linux/amd64"

# Download the Linux x86_64 emulator binary if missing or from a different fixture tag
if [ ! -f "$EMU_BINARY" ] || [ "$(cat "$EMU_TAG_FILE" 2>/dev/null)" != "$EMU_FIXTURES_TAG" ]; then
    echo "==> Downloading T3W1 emulator binary ($EMU_FIXTURES_TAG)..."
    gh release download "$EMU_FIXTURES_TAG" \
        --pattern 'trezor-emu-core-T3W1' \
        --repo "$(gh repo view --json nameWithOwner -q .nameWithOwner)" \
        --dir tests/fixtures/ \
        --clobber
    chmod +x "$EMU_BINARY"
    echo "$EMU_FIXTURES_TAG" > "$EMU_TAG_FILE"
fi

echo "==> Building Docker image ($PLATFORM)..."
docker build \
    --platform "$PLATFORM" \
    -f Dockerfile.emu-test \
    -t "$IMAGE_NAME" \
    .

if [ "${1:-}" = "--shell" ]; then
    echo "==> Starting interactive shell..."
    docker run \
        --platform "$PLATFORM" \
        --rm -it \
        "$IMAGE_NAME" \
        /bin/bash
else
    echo "==> Running emulator integration tests..."
    docker run \
        --platform "$PLATFORM" \
        --rm \
        "$IMAGE_NAME"
fi
