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

    let manager = BleManagerHandle::create()
        .await
        .expect("create BLE manager");
    let devices = manager
        .discover_trezor(8_000)
        .await
        .expect("discover emulator device");
    let device = devices
        .into_iter()
        .next()
        .expect("expected emulator device");

    let workflow = device
        .connect_ready_workflow_with_policy(skip_pairing_host_config(), None, true, None)
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

    let manager = BleManagerHandle::create()
        .await
        .expect("create BLE manager");
    let devices = manager
        .discover_trezor(8_000)
        .await
        .expect("discover emulator device");
    let device = devices
        .into_iter()
        .next()
        .expect("expected emulator device");

    let workflow = device
        .connect_ready_workflow_with_policy(skip_pairing_host_config(), None, true, None)
        .await
        .expect("bootstrap ready workflow");

    let signed = workflow
        .sign_message(SignMessageRequest {
            chain: Chain::Ethereum,
            path: ETH_PATH.to_string(),
            message: "hello from ffi emulator".to_string(),
            is_hex: false,
            chunkify: false,
            signers: Vec::new(),
        })
        .await
        .expect("sign ethereum message");

    assert!(signed.address.starts_with("0x"));
    assert!(signed.signature_formatted.starts_with("0x"));
    assert_eq!(signed.signature.len(), 65);
}

#[tokio::test]
#[ignore = "requires T3W1 emulator binary and Linux D-Bus (see CONTRIBUTING)"]
async fn emu_ble_ffi_sign_sol_message_with_given_signers() {
    let harness = EmulatorHarness::start();
    set_dbus_system_bus_address(harness.dbus_system_bus_address());

    let manager = BleManagerHandle::create()
        .await
        .expect("create BLE manager");
    let devices = manager
        .discover_trezor(8_000)
        .await
        .expect("discover emulator device");
    let device = devices
        .into_iter()
        .next()
        .expect("expected emulator device");

    let workflow = device
        .connect_ready_workflow_with_policy(skip_pairing_host_config(), None, true, None)
        .await
        .expect("bootstrap ready workflow");

    // Suite e2e fixture solanaSignMessage "additional signer and chunkify" (SLIP-14 seed).
    let signed = workflow
        .sign_message(SignMessageRequest {
            chain: Chain::Solana,
            path: "m/44'/501'/0'/0'".to_string(),
            message: "This is a longer test message that should be chunked across multiple display screens on the device".to_string(),
            is_hex: false,
            chunkify: true,
            signers: vec![
                "14CCvQzQzHCVgZM3j9soPnXuJXh1RmCfwLVUcdfbZVBS".to_string(),
                "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q".to_string(),
            ],
        })
        .await
        .expect("sign solana message");

    assert!(signed.address.is_empty());
    assert_eq!(
        signed.signature_formatted,
        "2dfa811d310f8eedcd945cbfcf3edd1abe319f051c3f9a111a75ee2280070a74b8635084fec9a5c629c65d752bc8223e735056f30764f8685c153160da2a1107"
    );
    assert_eq!(
        signed.signed_data.map(hex::encode).as_deref(),
        Some(
            "ff736f6c616e61206f6666636861696e010200d1699dcb1811b50bb0055f13044463128242e37a463b52f6c97a1f6eef88ad66c2f508c9c555cacc9fb26d88e88dd54e210bb5a8bce5687f60d7e75c4cd07f546869732069732061206c6f6e6765722074657374206d65737361676520746861742073686f756c64206265206368756e6b6564206163726f7373206d756c7469706c6520646973706c61792073637265656e73206f6e2074686520646576696365"
        )
    );
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
    // SAFETY: tests set the bus before any BLE manager state is created.
    unsafe {
        std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", value);
    }
}
