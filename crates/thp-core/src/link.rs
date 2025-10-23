use async_trait::async_trait;

#[async_trait]
pub trait Link {
    async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()>;
    async fn read(&mut self) -> anyhow::Result<Vec<u8>>;
    fn mtu(&self) -> usize;
}
