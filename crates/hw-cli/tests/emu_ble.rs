//! Integration tests that exercise the full BLE→THP stack against the Trezor
//! T3W1 emulator via the bluez-emu-bridge.
//!
//! These tests are `#[ignore]`d by default — they require:
//!   - Linux (D-Bus + BlueZ mock)
//!   - The T3W1 emulator binary (set `TREZOR_EMU_BINARY`)
//!   - The vendored bluez-emu-bridge (set `BRIDGE_DIR`)
//!   - Python 3 with `trezor`, `dbus-fast`, `click`, `typing-extensions`
//!
//! Run with:
//!   cargo test -p hw-cli --test emu_ble -- --ignored --nocapture --test-threads=1

use std::process::Command;

#[path = "../../../tests/fixtures/emulator_harness.rs"]
mod emulator_harness;

use emulator_harness::EmulatorHarness;

fn run_hw_cli(harness: &EmulatorHarness, args: &[&str]) -> (String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hw-cli"));
    cmd.env("DBUS_SYSTEM_BUS_ADDRESS", harness.dbus_system_bus_address());
    cmd.args(args);

    let output = cmd.output().expect("hw-cli failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    eprintln!("[test] stdout:\n{stdout}");
    eprintln!("[test] stderr:\n{stderr}");

    assert!(
        output.status.success(),
        "hw-cli exited non-zero\nstdout: {stdout}\nstderr: {stderr}"
    );

    (stdout, stderr)
}

/// Full BLE scan → connect → THP handshake → get ETH address.
#[test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
fn emu_ble_get_eth_address() {
    let harness = EmulatorHarness::start();

    let (stdout, _) = run_hw_cli(
        &harness,
        &[
            "-vv",
            "--skip-pairing",
            "address",
            "--chain",
            "eth",
            "--timeout-secs",
            "30",
            "--thp-timeout-secs",
            "60",
        ],
    );

    // SLIP-14 test seed produces a deterministic ETH address
    assert!(
        stdout.contains("0x"),
        "expected ETH address in output, got: {stdout}"
    );
}

/// Full BLE scan → connect → THP handshake → sign ETH transaction.
#[test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
fn emu_ble_sign_eth_tx() {
    let harness = EmulatorHarness::start();

    let tx_json = r#"{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x38d7ea4c68000"}"#;

    run_hw_cli(
        &harness,
        &[
            "-vv",
            "--skip-pairing",
            "sign",
            "eth",
            "--path",
            "m/44'/60'/0'/0/0",
            "--tx",
            tx_json,
            "--timeout-secs",
            "30",
            "--thp-timeout-secs",
            "60",
        ],
    );
}
