# Common Issues

Device testing, logs, and pairing/storage failures are covered in [docs/troubleshooting.md](../docs/troubleshooting.md).

- **Linux BLE build fails**: Install `sudo apt-get install -y libdbus-1-dev pkg-config`
- **`protoc` not found during build**: `thp-proto` vendors protoc via `protoc-bin-vendored`. If it still fails, check that the build script in `crates/thp-proto/build.rs` runs before dependent crates.
- **BLE pairing fails after firmware update**: Delete `~/.hw-core/thp-host.json` and re-pair, or use `cargo run -p hw-cli -- pair --force`.
- **Android `btleplug error: Not connected`**: Usually a stale OS-level BLE bond; see [docs/troubleshooting.md](../docs/troubleshooting.md#android).
- **`cargo test` fails on CI but passes locally**: CI runs on Linux without BLE hardware. Tests that require a real BLE device should be `#[ignore]`d or gated behind a feature flag.
- **UniFFI binding generation fails**: Ensure `hw-ffi` builds first (`cargo build -p hw-ffi`), then run the generate-bindings binary. Use `just bindings` which handles the correct order.
- **iOS simulator can't use BLE**: CoreBluetooth requires a physical device. Use `just run-ios-device` for BLE testing.
