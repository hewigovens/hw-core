//! Emulator-backed smoke tests for the Rust FFI surface.
//!
//! These tests reuse the Linux BlueZ emulator harness and exercise the same
//! public handle types that UniFFI exports to Swift/Kotlin consumers.

use hwcore::{
    BleManagerHandle, Chain, GetAddressRequest, HostConfig, PairingMethod, SessionPhase,
    SignMessageRequest, WorkflowEventKind,
};

#[path = "../../../tests/fixtures/emulator_harness.rs"]
mod emulator_harness;

use emulator_harness::EmulatorHarness;

const ETH_PATH: &str = "m/44'/60'/0'/0/0";

#[tokio::test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
async fn emu_ble_ffi_connect_ready_and_get_eth_address() {
    let harness = EmulatorHarness::start();
    set_dbus_system_bus_address(harness.dbus_system_bus_address());

    let manager = BleManagerHandle::new().await.expect("create BLE manager");
    let devices = manager
        .discover_trezor(8_000)
        .await
        .expect("discover emulator device");
    let device = devices
        .into_iter()
        .next()
        .expect("expected emulator device");

    let workflow = device
        .connect_ready_workflow(skip_pairing_host_config(), true)
        .await
        .expect("bootstrap ready workflow");

    let first_event = workflow
        .next_event(Some(500))
        .await
        .expect("receive ready event")
        .expect("expected initial workflow event");
    assert!(matches!(first_event.kind, WorkflowEventKind::Ready));
    assert_eq!(first_event.code, "SESSION_READY");

    let state = workflow.session_state().await.expect("query session state");
    assert!(matches!(state.phase, SessionPhase::Ready));

    let address = workflow
        .get_address(GetAddressRequest {
            chain: Chain::Ethereum,
            path: ETH_PATH.to_string(),
            show_on_device: false,
            include_public_key: false,
            chunkify: false,
        })
        .await
        .expect("fetch ethereum address");

    assert!(address.address.starts_with("0x"));
    assert_eq!(address.address.len(), 42);
}

#[tokio::test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
async fn emu_ble_ffi_sign_eth_message() {
    let harness = EmulatorHarness::start();
    set_dbus_system_bus_address(harness.dbus_system_bus_address());

    let manager = BleManagerHandle::new().await.expect("create BLE manager");
    let devices = manager
        .discover_trezor(8_000)
        .await
        .expect("discover emulator device");
    let device = devices
        .into_iter()
        .next()
        .expect("expected emulator device");

    let workflow = device
        .connect_ready_workflow(skip_pairing_host_config(), true)
        .await
        .expect("bootstrap ready workflow");

    let signed = workflow
        .sign_message(SignMessageRequest {
            chain: Chain::Ethereum,
            path: ETH_PATH.to_string(),
            message: "hello from ffi emulator".to_string(),
            is_hex: false,
            chunkify: false,
        })
        .await
        .expect("sign ethereum message");

    assert!(signed.address.starts_with("0x"));
    assert!(signed.signature_formatted.starts_with("0x"));
    assert_eq!(signed.signature.len(), 65);
}

fn skip_pairing_host_config() -> HostConfig {
    HostConfig {
        pairing_methods: vec![PairingMethod::SkipPairing],
        known_credentials: Vec::new(),
        static_key: None,
        host_name: "ffi-emu-test".to_string(),
        app_name: "hw-core/ffi".to_string(),
    }
}

fn set_dbus_system_bus_address(value: &str) {
    // SAFETY: emulator integration tests run in a dedicated single-threaded
    // process in CI (`--test-threads=1`) and set the bus before creating any
    // BLE manager state.
    unsafe {
        std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", value);
    }
}
