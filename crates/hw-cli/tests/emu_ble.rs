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
//!   cargo test -p hw-cli --test emu_ble -- --ignored --nocapture

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Manages the lifecycle of dbus-daemon + emulator + bridge processes.
struct EmulatorHarness {
    dbus: Child,
    emu: Child,
    bridge: Child,
    bus_address: String,
}

impl EmulatorHarness {
    fn start() -> Self {
        let emu_bin =
            std::env::var("TREZOR_EMU_BINARY").expect("TREZOR_EMU_BINARY env var not set");
        let bridge_dir = std::env::var("BRIDGE_DIR").expect("BRIDGE_DIR env var not set");

        // 1. Start a private D-Bus daemon using the vendored config.
        //    It prints its address on stdout before forking.
        let mut dbus = Command::new("dbus-daemon")
            .args([
                "--print-address",
                "--config-file",
                &format!("{bridge_dir}/bluez_emu_bridge/dbus-daemon.conf"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("dbus-daemon failed to start");

        let stdout = dbus.stdout.take().expect("dbus-daemon has no stdout");
        let mut reader = BufReader::new(stdout);
        let mut bus_address = String::new();
        reader
            .read_line(&mut bus_address)
            .expect("failed to read dbus-daemon address");
        let bus_address = bus_address.trim().to_string();

        // Strip guid= component for compatibility
        let bus_address: String = bus_address
            .split(',')
            .filter(|p| !p.starts_with("guid="))
            .collect::<Vec<_>>()
            .join(",");

        eprintln!("[harness] dbus-daemon at {bus_address}");
        std::thread::sleep(Duration::from_millis(500));

        // 2. Start the T3W1 emulator — headless, SLIP-14 test seed, fresh profile.
        let emu = Command::new(&emu_bin)
            .args(["--headless", "--slip0014", "--temporary-profile"])
            .env("SDL_VIDEODRIVER", "dummy")
            .env("TREZOR_DISABLE_ANIMATION", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("emulator failed to start");

        eprintln!("[harness] emulator started (pid {})", emu.id());
        std::thread::sleep(Duration::from_secs(3));

        // 3. Bridge: connects emulator UDP ports to the fake BlueZ D-Bus.
        let bridge = Command::new("python3")
            .arg(format!("{bridge_dir}/bluez-emu-bridge.py"))
            .args([
                "--emulator-port",
                "21328",
                "--bus-address",
                &bus_address,
            ])
            .env("PYTHONPATH", &bridge_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bluez-emu-bridge failed to start");

        eprintln!("[harness] bridge started (pid {})", bridge.id());
        std::thread::sleep(Duration::from_secs(1));

        Self {
            dbus,
            emu,
            bridge,
            bus_address,
        }
    }

    /// Returns the hw-cli Command pre-configured with the fake D-Bus address.
    fn hw_cli(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hw-cli"));
        cmd.env("DBUS_SYSTEM_BUS_ADDRESS", &self.bus_address);
        cmd
    }
}

impl Drop for EmulatorHarness {
    fn drop(&mut self) {
        eprintln!("[harness] tearing down...");
        let _ = self.bridge.kill();
        let _ = self.emu.kill();
        let _ = self.dbus.kill();
        let _ = self.bridge.wait();
        let _ = self.emu.wait();
        let _ = self.dbus.wait();
    }
}

/// Full BLE scan → connect → THP handshake → get ETH address.
#[test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
fn emu_ble_get_eth_address() {
    let harness = EmulatorHarness::start();

    let output = harness
        .hw_cli()
        .args([
            "-vv",
            "address",
            "--chain",
            "eth",
            "--timeout-secs",
            "30",
            "--thp-timeout-secs",
            "60",
        ])
        .output()
        .expect("hw-cli failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("[test] stdout:\n{stdout}");
    eprintln!("[test] stderr:\n{stderr}");

    assert!(
        output.status.success(),
        "hw-cli exited non-zero\nstdout: {stdout}\nstderr: {stderr}"
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

    let output = harness
        .hw_cli()
        .args([
            "-vv",
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
        ])
        .output()
        .expect("hw-cli failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    eprintln!("[test] stdout:\n{stdout}");
    eprintln!("[test] stderr:\n{stderr}");

    assert!(
        output.status.success(),
        "hw-cli exited non-zero\nstdout: {stdout}\nstderr: {stderr}"
    );
}
