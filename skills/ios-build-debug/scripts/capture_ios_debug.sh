#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-$PWD}"
OUT_DIR="${OUT_DIR:-/tmp/ios-debug}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$OUT_DIR/${TS}.log"
SCREENSHOT="$OUT_DIR/${TS}.png"
UI_DUMP="$OUT_DIR/${TS}.ui.json"

cd "$REPO_ROOT"

UDID="$(xcrun simctl list devices booted | awk -F '[()]' '/iPhone/{print $2; exit}')"
if [[ -z "$UDID" ]]; then
  UDID="$(xcrun simctl list devices available | awk -F '[()]' '/iPhone/{print $2; exit}')"
fi

if [[ -z "$UDID" ]]; then
  echo "No iPhone simulator found." >&2
  exit 1
fi

xcrun simctl boot "$UDID" >/dev/null 2>&1 || true
xcrun simctl bootstatus "$UDID" -b >/dev/null
open -a Simulator --args -CurrentDeviceUDID "$UDID" >/dev/null 2>&1 || true

xcrun simctl spawn "$UDID" log stream --style compact --level debug --predicate 'process == "HWCoreKitSampleAppiOS"' >"$LOG_FILE" 2>&1 &
LOG_PID=$!
cleanup() {
  kill "$LOG_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

just run-ios
sleep 2

xcrun simctl io "$UDID" screenshot "$SCREENSHOT" >/dev/null

if command -v axe >/dev/null 2>&1; then
  axe describe-ui --udid "$UDID" >"$UI_DUMP" || true
else
  UI_DUMP=""
fi

kill "$LOG_PID" >/dev/null 2>&1 || true
trap - EXIT

printf 'UDID=%s\n' "$UDID"
printf 'LOG_FILE=%s\n' "$LOG_FILE"
printf 'SCREENSHOT=%s\n' "$SCREENSHOT"
if [[ -n "$UI_DUMP" ]]; then
  printf 'UI_DUMP=%s\n' "$UI_DUMP"
fi
