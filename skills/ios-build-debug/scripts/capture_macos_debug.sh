#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${1:-$PWD}"
OUT_DIR="${OUT_DIR:-/tmp/macos-debug}"
APP_NAME="${APP_NAME:-HWCoreKitSampleApp}"
mkdir -p "$OUT_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$OUT_DIR/${TS}.log"
RUN_LOG="$OUT_DIR/${TS}.run.log"
SCREENSHOT="$OUT_DIR/${TS}.png"

cd "$REPO_ROOT"

log stream --style compact --level debug --predicate "process == \"${APP_NAME}\"" >"$LOG_FILE" 2>&1 &
LOG_PID=$!

just run-mac >"$RUN_LOG" 2>&1 &
APP_PID=$!
APP_RUNNING="false"

cleanup() {
  kill "$APP_PID" >/dev/null 2>&1 || true
  kill "$LOG_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 20); do
  if pgrep -x "$APP_NAME" >/dev/null 2>&1; then
    APP_RUNNING="true"
    break
  fi
  sleep 1
done

if [[ "$APP_RUNNING" == "true" ]]; then
  osascript -e "tell application \"${APP_NAME}\" to activate" >/dev/null 2>&1 || true
  sleep 1
fi

WINDOW_ID="$(osascript <<OSA 2>/dev/null || true
tell application "System Events"
  try
    return value of attribute "AXWindowNumber" of window 1 of process "${APP_NAME}"
  on error
    return ""
  end try
end tell
OSA
)"

if [[ -n "$WINDOW_ID" ]]; then
  if ! screencapture -x -l "$WINDOW_ID" "$SCREENSHOT"; then
    SCREENSHOT=""
  fi
elif ! screencapture -x "$SCREENSHOT"; then
  SCREENSHOT=""
fi

printf 'APP_PID=%s\n' "$APP_PID"
printf 'APP_RUNNING=%s\n' "$APP_RUNNING"
printf 'LOG_FILE=%s\n' "$LOG_FILE"
printf 'RUN_LOG=%s\n' "$RUN_LOG"
if [[ -n "$SCREENSHOT" ]]; then
  printf 'SCREENSHOT=%s\n' "$SCREENSHOT"
else
  printf 'SCREENSHOT=unavailable\n'
fi
