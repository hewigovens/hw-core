# hw-core

A Rust SDK for hardware wallet communication. The first supported device is Trezor Safe 7 over Bluetooth Low Energy (BLE), using the Trezor Host Protocol (THP).

```toml
[dependencies]
hw-core = "0.1.1"
```

## Rust API

- `hw_core::wallet`: shared connection, session, derivation-path, and signing utilities.
- `hw_core::trezor`: Trezor THP workflows, requests, credential storage, and the BLE backend.
- `hw_core::transport`: BLE discovery, connections, and byte I/O.
- `hw_core::{Chain, ChainConfig, WalletError, WalletErrorKind, WalletResult}`: shared types.

Resolve a chain's default derivation path:

```rust
use hw_core::{Chain, wallet::chain::ResolvedDerivationPath};

let resolved = ResolvedDerivationPath::resolve(Some(Chain::Ethereum), None)?;
assert_eq!(resolved.chain, Chain::Ethereum);
assert_eq!(resolved.path, Chain::Ethereum.default_path());
# Ok::<(), hw_core::WalletError>(())
```

Discover a Trezor Safe 7 from an async Tokio application:

```rust,no_run
use std::time::Duration;
use hw_core::{
    WalletResult,
    transport::{BleManager, BleProfile, DiscoveredDevice},
    wallet::ble::scan_profile_until_match,
};

async fn discover() -> WalletResult<Vec<DiscoveredDevice>> {
    let manager = BleManager::new().await?;
    scan_profile_until_match(
        &manager,
        BleProfile::TREZOR_SAFE7,
        Duration::from_secs(5),
        None,
    ).await
}
```

Use `wallet::ble::connect_and_bootstrap_session` to connect and prepare a THP session, or `trezor::thp::ThpWorkflow` to drive pairing and session transitions with your own UI.

## Embedding in an app

Apps that ship their own Rust core can depend on these crates instead of the UniFFI library:

- Implement `trezor::thp::ThpStorage` to keep the pairing snapshot (`HostSnapshot`) in the platform's secure storage. It holds the host's static private key and the device-issued pairing credentials, so never write it to a plain file or log it.
- `trezor::ble::BleBackend::set_event_sink` reports each device prompt (`ButtonRequest`) as the device shows it, and `BleBackend::cancel_handle` cancels that prompt in-session without dropping the channel.
- `WalletError::kind()` classifies failures (rejected on device, locked, busy, disconnected, pairing required, unsupported, ...) without matching message text.

`hw-core` always enables BLE (`trezor-connect/ble`, which pulls in btleplug). To use the THP workflow with your own transport, depend on `trezor-connect` without the `ble` feature and implement `trezor::thp::ThpBackend`. The CLI (`hw-cli`) and UniFFI (`hw-ffi`) crates are separate and never pulled in.

## Ethereum definitions

Trezor firmware shows unknown EVM networks, tokens, and contract calls as "unknown" unless the host sends signed definitions. hw-core never downloads them: the app fetches or bundles the `*.dat` files and passes their bytes.

- `EthSignTx::with_definitions` sends the network, token, and display-format definitions with the sign request; `GetAddressRequest`, `SignMessageRequest`, and `SignTypedDataRequest` take `with_encoded_network`.
- `EthSignTx::with_definition_catalog` holds extra token and display-format definitions. A non-empty catalog lets the firmware ask for one mid-signing (`EthereumDefinitionRequest`); hw-core answers from the catalog, or with no definitions when nothing matches.
- `EthDefinitionsVersion::for_firmware` picks the format the device accepts (v2 from Core 2.13.0 / Legacy 1.14.2, v1 before) and builds the data.trezor.io URLs Trezor Suite uses:

```rust
use hw_core::trezor::thp::{DeviceFeatures, EthDefinitionsVersion};

let features = DeviceFeatures { major_version: 2, minor_version: 13, ..Default::default() };
let version = EthDefinitionsVersion::for_firmware(&features);
assert_eq!(
    version.network_url(8453),
    "https://data.trezor.io/firmware/definitions/v2/eth/chain-id/8453/network.dat"
);
```

Token files live at `chain-id/{chain_id}/token-{address}.dat` and display formats at `chain-id/{chain_id}/display-format/{address}-{selector}.dat`, with lowercase hex and no `0x`. The UniFFI library exposes the same through `EthereumDefinitions` on `SignTxRequest` and `EthereumDefinitionsSource`.

## Versioning

The crates are released together with one version. Before 1.0, a minor release (`0.x` → `0.(x+1)`) may break the public API and a patch release does not, so depend on `hw-core = "0.x"` with a caret requirement. Breaking changes are listed in the release notes. Public enums such as `WalletErrorKind` gain variants in minor releases, and new `ThpBackend` methods are also minor-release changes.

## Platforms and status

This is an early-stage SDK. macOS and Linux are the supported CLI hosts; native Apple and Android apps use the project's separate UniFFI integrations. Linux builds require `libdbus-1-dev` and `pkg-config`. BLE access also requires the host platform's Bluetooth permissions.

See the [project README](https://github.com/hewigovens/hw-core#status) for supported operations and known limitations, and the [contribution guide](https://github.com/hewigovens/hw-core/blob/main/CONTRIBUTING.md) for build, bindings, and emulator setup.

Licensed under Apache-2.0.
