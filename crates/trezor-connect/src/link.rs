use ble_transport::BleLink;
use thp_core::Link;

/// A wrapper around `BleLink` that implements `thp_core::Link`.
pub struct BleThpLink {
    inner: BleLink,
}

impl BleThpLink {
    pub fn new(link: BleLink) -> Self {
        Self { inner: link }
    }

    pub fn into_inner(self) -> BleLink {
        self.inner
    }
}

impl Link for BleThpLink {
    async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        self.inner.write(chunk).await
    }

    async fn read(&mut self) -> anyhow::Result<Vec<u8>> {
        self.inner.read().await
    }

    fn mtu(&self) -> usize {
        self.inner.mtu()
    }
}
