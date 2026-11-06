use crate::LedgerError;
use ble_transport::BleLink;

pub(super) trait PacketIo: Send {
    fn write(
        &mut self,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = Result<(), LedgerError>> + Send;
    fn read(&mut self) -> impl std::future::Future<Output = Result<Vec<u8>, LedgerError>> + Send;
    async fn disconnect(&mut self) -> Result<(), LedgerError>;
    fn mtu(&self) -> usize;
}

impl PacketIo for BleLink {
    async fn write(&mut self, bytes: &[u8]) -> Result<(), LedgerError> {
        Ok(BleLink::write(self, bytes).await?)
    }
    async fn read(&mut self) -> Result<Vec<u8>, LedgerError> {
        Ok(BleLink::read(self).await?)
    }
    async fn disconnect(&mut self) -> Result<(), LedgerError> {
        Ok(BleLink::disconnect(self).await?)
    }
    fn mtu(&self) -> usize {
        BleLink::mtu(self)
    }
}
