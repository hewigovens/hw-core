use super::channel::BleChannel;
use crate::{ApduTransport, LedgerError};
use ble_transport::{BleLink, BleSession};
use std::time::Duration;

pub struct LedgerBleTransport {
    channel: BleChannel<BleLink>,
}

impl LedgerBleTransport {
    pub async fn new(
        session: BleSession,
        operation_timeout: Duration,
    ) -> Result<Self, LedgerError> {
        let (_, link) = session.into_parts();
        Ok(Self {
            channel: BleChannel::new(link, operation_timeout).await?,
        })
    }

    pub async fn disconnect(&mut self) -> Result<(), LedgerError> {
        self.channel.disconnect().await
    }
}

impl ApduTransport for LedgerBleTransport {
    async fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError> {
        self.channel.exchange(command).await
    }
}
