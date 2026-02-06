# ble-transport

BLE transport primitives for hardware wallet SDKs.

This crate provides a high-level wrapper around `btleplug` for discovering and connecting to hardware wallets over BLE. It handles:
- Scanning for devices with specific service UUIDs
- Managing connections and subscriptions
- buffering notifications

## Key Components

- `BleManager`: Manages scanning and discovery of devices.
- `BleSession`: Represents an active connection to a device. It can be converted into a `BleLink` for raw I/O.
- `BleLink`: A lower-level wrapper around the BLE characteristic writer and notification receiver.

## Usage

```rust
use ble_transport::{BleManager, ScanOptions};
use std::time::Duration;

async fn scan_and_connect() -> Result<(), Box<dyn std::error::Error>> {
    let manager = BleManager::new().await?;
    let mut scan = manager.scan(ScanOptions::default()).await?;

    while let Some(event) = scan.next().await {
        if let ble_transport::ScanEvent::Found(device) = event {
            println!("Found device: {:?}", device);
            let session = manager.connect(&device).await?;
            // Use session...
            break;
        }
    }
    Ok(())
}
```
