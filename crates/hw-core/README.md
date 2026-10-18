# hw-core

A Rust SDK for hardware wallet communication. The first supported device is
Trezor Safe 7 over Bluetooth Low Energy (BLE), using the Trezor Host Protocol (THP).

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

Use `wallet::ble::connect_and_bootstrap_session` to connect and prepare a THP
session, or `trezor::thp::ThpWorkflow` to drive pairing and session transitions
with your own UI.

## Platforms and status

This is an early-stage SDK. macOS and Linux are the supported CLI hosts; native
Apple and Android apps use the project's separate UniFFI integrations. Linux
builds require `libdbus-1-dev` and `pkg-config`. BLE access also requires the host
platform's Bluetooth permissions.

See the [project README](https://github.com/hewigovens/hw-core#status) for supported
operations and known limitations, and the
[contribution guide](https://github.com/hewigovens/hw-core/blob/main/CONTRIBUTING.md)
for build, bindings, and emulator setup.

Licensed under Apache-2.0.
