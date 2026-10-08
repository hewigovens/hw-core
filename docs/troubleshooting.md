# Troubleshooting

How to get logs from each surface, and fixes for failures seen on real devices.

## Getting logs

| Surface | How |
|---|---|
| CLI | Add `-vv` to any command, e.g. `cargo run -p hw-cli -- -vv address --chain eth`. THP packets and retries are logged at `trace`/`debug`. |
| Android sample | `just android-logs` streams logcat filtered to hw-core tags (`HWCoreSample`, `hwcore-rs`, `HWCoreBtleplug`, …). `just run-android` installs, launches and streams in one step. |
| iOS sample | `just run-ios-device` builds, installs and streams the app console via `xcrun devicectl device process launch --console`. |
| Sample app UI | Both sample apps show their workflow log on screen; it matches the `HWCoreSample` / console lines. |

`trezor-thp` logs through the `log` crate, which the `tracing` setup does not capture. Transport behavior is still visible through hw-core's own `trace` lines.

## Android

- **`adb: command not found`**: the SDK ships it at `~/Library/Android/sdk/platform-tools/adb`. `scripts/adb.sh` and the `just` recipes find it there; to use it directly, add that directory to `PATH`.
- **`INSTALL_FAILED_UPDATE_INCOMPATIBLE`**: an installed `dev.hewig.hwcore` was signed with a different key. Uninstall it first (`adb uninstall dev.hewig.hwcore`); this deletes the app's saved pairing.
- **Logs from the failure are missing**: some vendor builds flood logcat and the buffer rotates within a minute. Enlarge it with `adb logcat -G 16M` and filter by tag, e.g. `adb logcat HWCoreSample:V hwcore-rs:V AndroidRuntime:V '*:S'`.
- **Crash or error?** If `adb shell pidof dev.hewig.hwcore` still returns a pid and `adb logcat -b crash -d` is empty, the app did not crash; look for an `ERROR:` line from `HWCoreSample` instead.
- **`BLE error: btleplug error: Not connected`**: usually a stale OS-level BLE bond to the Trezor (for example after the device was re-paired elsewhere). Check with `adb shell dumpsys bluetooth_manager | grep -A3 'Bonded devices'`. App-created bonds may be hidden from the main Bluetooth list; remove it under "See all" / previously connected devices, or forget the phone on the Trezor, then pair again.

## iOS

- **BLE does not work in the simulator**: CoreBluetooth needs a physical device; use `just run-ios-device`.
- **Device not found**: `xcrun devicectl list devices` must show the iPhone as `connected`; set `DEVICE_ID=<UDID>` to pick one explicitly.

## Pairing and storage

- **`storage directory must not be writable by group or others`**: hw-core refuses to keep credentials in a directory other users or groups can write to, and checks the file's direct parent. Pass a path inside a dedicated subdirectory (hw-core creates it owner-only), e.g. `filesDir/hwcore/thp-host.json` on Android, not a file directly in a shared directory. Android's `filesDir` itself is group-writable.
- **Pairing fails after a firmware update or device wipe**: the stored credential no longer matches. Re-pair with `cargo run -p hw-cli -- pair --force`, or delete the app's storage file (CLI: `~/.hw-core/thp-host.json`).
- **Device locked**: connect with `try_to_unlock` (the CLI default) so the Trezor prompts for the PIN; otherwise the handshake fails with `DeviceLocked`.

## Emulator tests

See [CONTRIBUTING.md](../CONTRIBUTING.md#emulator-integration-tests) for running the T3W1 emulator suite. `./scripts/test-emu-docker.sh` mirrors CI on any host.
