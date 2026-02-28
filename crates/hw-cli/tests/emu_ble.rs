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

use std::io::{BufRead, BufReader, Read};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

static HARNESS_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Manages the lifecycle of dbus-daemon + emulator + bridge processes.
struct EmulatorHarness {
    dbus: Child,
    emu: Child,
    bridge: Child,
    bus_address: String,
    profile_dir: PathBuf,
}

impl EmulatorHarness {
    fn start() -> Self {
        let emu_bin =
            std::env::var("TREZOR_EMU_BINARY").expect("TREZOR_EMU_BINARY env var not set");
        let bridge_dir = std::env::var("BRIDGE_DIR").expect("BRIDGE_DIR env var not set");

        // 1. Start a private D-Bus daemon using the vendored config.
        //    It prints its address on stdout before forking — we read that line
        //    as the readiness signal (no fixed sleep needed).
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

        eprintln!("[harness] dbus-daemon ready at {bus_address}");

        // 2. Start the T3W1 emulator — headless, fresh profile.
        //    The binary is a MicroPython executable; headless/animation are
        //    controlled via environment variables, not CLI flags.
        //    Each harness gets a unique profile dir so tests don't share state.
        let id = HARNESS_COUNTER.fetch_add(1, Ordering::SeqCst);
        let profile_dir = std::env::temp_dir().join(format!(
            "trezor-emu-{}-{}",
            std::process::id(),
            id
        ));
        // Remove any stale profile from a previous run, then create fresh.
        let _ = std::fs::remove_dir_all(&profile_dir);
        std::fs::create_dir_all(&profile_dir).expect("failed to create profile dir");

        let emu = Command::new(&emu_bin)
            .args(["-O0", "-m", "main"])
            .env("SDL_VIDEODRIVER", "dummy")
            .env("TREZOR_DISABLE_ANIMATION", "1")
            .env("TREZOR_PROFILE_DIR", &profile_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("emulator failed to start");

        eprintln!("[harness] emulator started (pid {})", emu.id());

        // 3. Bridge: connects emulator BLE UDP ports to the fake BlueZ D-Bus.
        //    BLE data port = 21324 + 4 = 21328.
        //    Started early so it can initialize while we wait for the emulator.
        let bridge = Command::new("python3")
            .arg(format!("{bridge_dir}/bluez-emu-bridge.py"))
            .args(["--emulator-port", "21328", "--bus-address", &bus_address])
            .env("PYTHONPATH", &bridge_dir)
            .env("PYTHONUNBUFFERED", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bluez-emu-bridge failed to start");

        // Build the harness struct now so that Drop cleans up all processes
        // if any of the readiness checks below panic.
        let mut harness = Self {
            dbus,
            emu,
            bridge,
            bus_address,
            profile_dir,
        };

        // Wait for the emulator to be ready by probing its BLE event port.
        // BLE event port = TREZOR_UDP_PORT (default 21324) + 5 = 21329.
        wait_for_emulator_ready(21329, Duration::from_secs(30));
        eprintln!("[harness] emulator ready (UDP responsive)");

        // Load the SLIP-14 test seed via debuglink (USB port 21324).
        let load_seed = Command::new("python3")
            .arg(format!("{bridge_dir}/load-seed.py"))
            .arg("21324")
            .env("PYTHONPATH", &bridge_dir)
            .output()
            .expect("load-seed.py failed to execute");
        assert!(
            load_seed.status.success(),
            "load-seed.py failed:\n{}",
            String::from_utf8_lossy(&load_seed.stderr)
        );
        eprintln!("[harness] SLIP-14 seed loaded");

        // Wait for the bridge to log its ready message to stderr.
        wait_for_output(&mut harness.bridge, Duration::from_secs(30));
        eprintln!("[harness] bridge ready");

        harness
    }

    /// Run hw-cli with the given args against this harness, returning (stdout, stderr).
    /// Panics if the command exits non-zero.
    fn run_hw_cli(&self, args: &[&str]) -> (String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hw-cli"));
        cmd.env("DBUS_SYSTEM_BUS_ADDRESS", &self.bus_address);
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
        let _ = std::fs::remove_dir_all(&self.profile_dir);
    }
}

/// Probe the emulator's UDP event port until it responds or timeout is reached.
/// Sends a minimal "ping" datagram (EventType::EMULATOR_PING = 255).
fn wait_for_emulator_ready(event_port: u16, timeout: Duration) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("failed to bind UDP socket");
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let addr = format!("127.0.0.1:{event_port}");

    // Minimal Event struct: event_type(u32le) + connection_id(u32le) + data_len(u8)
    // EventType::EMULATOR_PING = 255
    let ping: [u8; 9] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let start = Instant::now();
    loop {
        let _ = sock.send_to(&ping, &addr);
        let mut buf = [0u8; 64];
        if sock.recv_from(&mut buf).is_ok() {
            return;
        }
        if start.elapsed() > timeout {
            panic!("emulator did not become ready within {timeout:?}");
        }
    }
}

/// Wait until a child process produces at least one byte on stderr,
/// indicating it has started up and is logging.
fn wait_for_output(child: &mut Child, timeout: Duration) {
    let stderr = child.stderr.take().expect("child has no stderr");
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut buf = [0u8; 1];
        if reader.read(&mut buf).is_ok() {
            let _ = tx.send(());
        }
    });

    rx.recv_timeout(timeout)
        .expect("child process produced no output within timeout");
}

/// Full BLE scan → connect → THP handshake → get ETH address.
#[test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
fn emu_ble_get_eth_address() {
    let harness = EmulatorHarness::start();

    let (stdout, _) = harness.run_hw_cli(&[
        "-vv",
        "--skip-pairing",
        "address",
        "--chain",
        "eth",
        "--timeout-secs",
        "30",
        "--thp-timeout-secs",
        "60",
    ]);

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

    harness.run_hw_cli(&[
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
    ]);
}
