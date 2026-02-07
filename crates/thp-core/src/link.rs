pub trait Link {
    fn write(
        &mut self,
        chunk: &[u8],
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    fn read(&mut self) -> impl std::future::Future<Output = anyhow::Result<Vec<u8>>> + Send;
    fn mtu(&self) -> usize;
}
