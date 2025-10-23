use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct TrustedPeer {
    pub device_id: String,
    pub peer_static_key: Vec<u8>,
    pub established_at_ms: u64,
}

#[async_trait]
pub trait TrustStore: Send + Sync {
    async fn get(&self, device_id: &str) -> anyhow::Result<Option<TrustedPeer>>;
    async fn put(&self, peer: TrustedPeer) -> anyhow::Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct MemoryTrustStore {
    inner: Arc<RwLock<HashMap<String, TrustedPeer>>>,
}

#[async_trait]
impl TrustStore for MemoryTrustStore {
    async fn get(&self, device_id: &str) -> anyhow::Result<Option<TrustedPeer>> {
        Ok(self.inner.read().get(device_id).cloned())
    }

    async fn put(&self, peer: TrustedPeer) -> anyhow::Result<()> {
        self.inner.write().insert(peer.device_id.clone(), peer);
        Ok(())
    }
}
