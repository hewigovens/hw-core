use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;
use thp_core::link::Link;
use thp_core::trust::MemoryTrustStore;
use thp_core::{HandshakeEvent, HandshakeOpts, ThpError, ThpSession};

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("handshake failed: {0}")]
    Handshake(#[from] ThpError),
}

/// Maintains a THP session lifecycle for a given link.
#[derive(Default)]
pub struct ThpTransport {
    session: Option<ThpSession>,
}

impl ThpTransport {
    pub fn new() -> Self {
        Self { session: None }
    }

    pub fn session(&self) -> Option<&ThpSession> {
        self.session.as_ref()
    }

    pub async fn ensure_session<L>(
        &mut self,
        link: &mut L,
        device_id: &str,
        app_id: Option<Vec<u8>>,
        timeout: Duration,
        on_event: impl Fn(HandshakeEvent) + Send + Sync + Copy,
    ) -> Result<&ThpSession, TransportError>
    where
        L: Link + Send,
    {
        if self.session.is_none() {
            let opts = HandshakeOpts {
                device_id: device_id.to_owned(),
                handshake_timeout: timeout,
                trust_store: Arc::new(MemoryTrustStore::default()),
                app_id,
            };
            let session = ThpSession::handshake(link, opts, |event| on_event(event)).await?;
            self.session = Some(session);
        }
        Ok(self.session.as_ref().expect("session initialized"))
    }

    pub async fn request<L>(
        &mut self,
        link: &mut L,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, TransportError>
    where
        L: Link + Send,
    {
        let session = self
            .session
            .as_ref()
            .expect("session must be established before request");
        let response = session.request(link, payload, timeout).await?;
        Ok(response)
    }

    pub fn reset(&mut self) {
        self.session = None;
    }
}
