# thp-core

Core host-side state machine for the Trezor Host Protocol (THP).

This crate implements the platform-agnostic session logic for THP, handling:
- Noise XX handshake orchestration
- Encrypted message transport
- Trust store management for paired devices

## Key Components

- `ThpSession`: The main entry point for establishing a session. It manages the Noise state and message framing.
- `Link`: A trait that abstracts the underlying transport (e.g., BLE). Implement this trait to adapt `ThpSession` to your specific transport layer.
- `TrustStore`: A trait for persisting trusted peer credentials.

## Usage

To establish a session, you need an implementation of the `Link` trait.

```rust
use thp_core::{ThpSession, HandshakeOpts, Link};
use std::sync::Arc;

async fn connect<L: Link + Send>(link: &mut L) -> Result<ThpSession, thp_core::ThpError> {
    let opts = HandshakeOpts {
        device_id: "device-id".to_string(),
        handshake_timeout: std::time::Duration::from_secs(5),
        trust_store: Arc::new(thp_core::MemoryTrustStore::default()),
        app_id: None,
    };

    ThpSession::handshake(link, opts, |event| {
        println!("Handshake event: {:?}", event);
    }).await
}
```
