#!/usr/bin/env bash
# Usage: adb.sh devices | logs | launch <log_file>
set -euo pipefail

LOG_FILTER="HWCoreSample|HWCoreBtleplug|hwcore-rs|hwcore JNI_OnLoad|BLE THP|THP create_channel|trezor_connect|ble_transport|hw_wallet|WF |AndroidRuntime|JNI DETECTED ERROR|Connect failed|Pair only failed|btleplug droidplug"

find_adb() {
  ADB_BIN="$(command -v adb || true)"
  if [[ -z "$ADB_BIN" ]]; then
    for candidate in "${ANDROID_SDK_ROOT:-}/platform-tools/adb" "${ANDROID_HOME:-}/platform-tools/adb" "$HOME/Library/Android/sdk/platform-tools/adb" "/opt/homebrew/share/android-commandlinetools/platform-tools/adb"; do
      if [[ -x "$candidate" ]]; then
        ADB_BIN="$candidate"
        break
      fi
    done
  fi
  if [[ -z "$ADB_BIN" ]]; then
    echo "adb not found. Install Android platform-tools or add adb to PATH." >&2
    exit 1
  fi
}

select_device() {
  "$ADB_BIN" start-server >/dev/null
  if [[ -z "${ANDROID_SERIAL:-}" ]]; then
    ANDROID_SERIAL="$(
      "$ADB_BIN" devices \
        | awk 'NR > 1 && $2 == "device" { print $1; exit }'
    )"
    if [[ -z "$ANDROID_SERIAL" ]]; then
      "$ADB_BIN" devices -l
      echo "No connected Android device found. Set ANDROID_SERIAL if needed." >&2
      exit 1
    fi
  fi
}

stream_logs() {
  "$ADB_BIN" -s "$ANDROID_SERIAL" logcat -v time | "$@" | rg --line-buffered "$LOG_FILTER"
}

find_adb
case "${1:-}" in
  devices)
    "$ADB_BIN" devices -l
    ;;
  logs)
    select_device
    "$ADB_BIN" -s "$ANDROID_SERIAL" logcat -c
    echo "Streaming logs from $ANDROID_SERIAL (Ctrl+C to stop)..."
    stream_logs cat
    ;;
  launch)
    log_file="${2:?log file required}"
    echo "Using adb: $ADB_BIN"
    select_device
    "$ADB_BIN" -s "$ANDROID_SERIAL" wait-for-device
    mkdir -p "$(dirname "$log_file")"
    "$ADB_BIN" -s "$ANDROID_SERIAL" logcat -c
    "$ADB_BIN" -s "$ANDROID_SERIAL" shell am start -n dev.hewig.hwcore/.MainActivity
    echo "Launched dev.hewig.hwcore on device: $ANDROID_SERIAL"
    echo "Streaming logs from $ANDROID_SERIAL to $log_file (Ctrl+C to stop)..."
    stream_logs tee "$log_file"
    ;;
  *)
    echo "usage: $0 devices | logs | launch <log_file>" >&2
    exit 1
    ;;
esac
