# ble-transport

BLE transport primitives for hardware wallet SDKs.

This crate provides a high-level wrapper around `btleplug` for discovering and connecting to hardware wallets over BLE. It handles:
- Scanning for devices with specific service UUIDs
- Managing connections and subscriptions
- buffering notifications

## Key Components

- `BleManager`: Manages scanning and discovery of devices.
- `DiscoveredDevice`: A scanned device; `connect` opens a `BleSession`.
- `BleSession`: Represents an active connection to a device. `into_parts` yields a `BleLink` for raw I/O.
- `BleLink`: A lower-level wrapper around the BLE characteristic writer and notification receiver.

## Usage

```rust
use ble_transport::{BleManager, BleProfile};
use std::time::Duration;

async fn scan_and_connect() -> Result<(), Box<dyn std::error::Error>> {
    let profile = BleProfile::TREZOR_SAFE7;
    let manager = BleManager::new().await?;
    let devices = manager.scan_profile(profile, Duration::from_secs(5)).await?;
    if let Some(device) = devices.into_iter().next() {
        let session = device.connect(profile).await?;
        let (_info, _link) = session.into_parts();
    }
    Ok(())
}
```
