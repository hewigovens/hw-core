use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

static HARNESS_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Manages the lifecycle of dbus-daemon + emulator + bridge + auto-confirm processes.
pub struct EmulatorHarness {
    dbus: Child,
    emu: Child,
    bridge: Child,
    auto_confirm: Child,
    bus_address: String,
    profile_dir: PathBuf,
}

impl EmulatorHarness {
    pub fn start() -> Self {
        let emu_bin =
            std::env::var("TREZOR_EMU_BINARY").expect("TREZOR_EMU_BINARY env var not set");
        let bridge_dir = std::env::var("BRIDGE_DIR").expect("BRIDGE_DIR env var not set");

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

        let bus_address: String = bus_address
            .split(',')
            .filter(|part| !part.starts_with("guid="))
            .collect::<Vec<_>>()
            .join(",");

        eprintln!("[harness] dbus-daemon ready at {bus_address}");

        let id = HARNESS_COUNTER.fetch_add(1, Ordering::SeqCst);
        let profile_dir =
            std::env::temp_dir().join(format!("trezor-emu-{}-{}", std::process::id(), id));
        let _ = std::fs::remove_dir_all(&profile_dir);
        std::fs::create_dir_all(&profile_dir).expect("failed to create profile dir");

        let emu = Command::new(&emu_bin)
            .args(["-O0", "-m", "main"])
            .env("SDL_VIDEODRIVER", "dummy")
            .env("TREZOR_DISABLE_ANIMATION", "1")
            .env("TREZOR_PROFILE_DIR", &profile_dir)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("emulator failed to start");

        eprintln!("[harness] emulator started (pid {})", emu.id());

        let bridge = Command::new("python3")
            .arg(format!("{bridge_dir}/bluez-emu-bridge.py"))
            .args(["--emulator-port", "21328", "--bus-address", &bus_address])
            .env("PYTHONPATH", &bridge_dir)
            .env("PYTHONUNBUFFERED", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("bluez-emu-bridge failed to start");

        let auto_confirm_placeholder = Command::new("true")
            .spawn()
            .expect("placeholder spawn failed");

        let mut harness = Self {
            dbus,
            emu,
            bridge,
            auto_confirm: auto_confirm_placeholder,
            bus_address,
            profile_dir,
        };

        wait_for_emulator_ready(21329, Duration::from_secs(30));
        eprintln!("[harness] emulator ready (UDP responsive)");

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

        let auto_confirm = Command::new("python3")
            .arg(format!("{bridge_dir}/auto-confirm.py"))
            .arg("21325")
            .arg("15")
            .env("PYTHONPATH", &bridge_dir)
            .env("PYTHONUNBUFFERED", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("auto-confirm.py failed to start");
        harness.auto_confirm = auto_confirm;

        wait_for_output(&mut harness.auto_confirm, Duration::from_secs(10));
        eprintln!("[harness] auto-confirm ready");

        wait_for_output(&mut harness.bridge, Duration::from_secs(30));
        eprintln!("[harness] bridge ready");

        harness
    }

    pub fn dbus_system_bus_address(&self) -> &str {
        &self.bus_address
    }
}

impl Drop for EmulatorHarness {
    fn drop(&mut self) {
        eprintln!("[harness] tearing down...");
        let _ = self.auto_confirm.kill();
        let _ = self.bridge.kill();
        let _ = self.emu.kill();
        let _ = self.dbus.kill();
        let _ = self.auto_confirm.wait();
        let _ = self.bridge.wait();
        let _ = self.emu.wait();
        let _ = self.dbus.wait();
        let _ = std::fs::remove_dir_all(&self.profile_dir);
    }
}

fn wait_for_emulator_ready(event_port: u16, timeout: Duration) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("failed to bind UDP socket");
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let addr = format!("127.0.0.1:{event_port}");
    let ping: [u8; 9] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let start = Instant::now();
    loop {
        let _ = sock.send_to(&ping, &addr);
        let mut buf = [0u8; 64];
        if sock.recv_from(&mut buf).is_ok() {
            return;
        }
        assert!(
            start.elapsed() <= timeout,
            "emulator did not become ready within {timeout:?}"
        );
    }
}

fn wait_for_output(child: &mut Child, timeout: Duration) {
    let stderr = child.stderr.take().expect("child has no stderr");
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() && !line.is_empty() {
            let _ = tx.send(());
        }
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    rx.recv_timeout(timeout)
        .expect("child process produced no output within timeout");
}
