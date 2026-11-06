use super::packet_io::PacketIo;
use crate::framing::{BleFrames, BleResponse};
use crate::{ApduTransport, LedgerError, protocol::BLE_MTU_COMMAND};
use std::time::Duration;
use tokio::time::timeout;

pub(super) struct BleChannel<I> {
    link: I,
    frame_size: usize,
    timeout: Duration,
    ready: bool,
}

impl<I: PacketIo> BleChannel<I> {
    pub(super) async fn new(link: I, operation_timeout: Duration) -> Result<Self, LedgerError> {
        if operation_timeout.is_zero() {
            return Err(LedgerError::InvalidInput("timeout must be positive"));
        }
        let mut transport = Self {
            link,
            frame_size: 20,
            timeout: operation_timeout,
            ready: false,
        };
        let result = timeout(operation_timeout, transport.negotiate())
            .await
            .map_err(|_| LedgerError::Timeout)
            .and_then(|result| result);
        if let Err(error) = result {
            let _ = timeout(Duration::from_secs(2), transport.link.disconnect()).await;
            return Err(error);
        }
        transport.ready = true;
        Ok(transport)
    }

    async fn negotiate(&mut self) -> Result<(), LedgerError> {
        self.link.write(&[BLE_MTU_COMMAND, 0, 0, 0, 0]).await?;
        let response = self.link.read().await?;
        if response.len() != 6 || response[0] != BLE_MTU_COMMAND || response[5] < 6 {
            return Err(LedgerError::Protocol("invalid MTU response"));
        }
        // A smaller frame is valid and avoids exceeding platform write limits.
        self.frame_size = usize::from(response[5]).min(self.link.mtu());
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<(), LedgerError> {
        self.ready = false;
        timeout(self.timeout, self.link.disconnect())
            .await
            .map_err(|_| LedgerError::Timeout)??;
        Ok(())
    }

    async fn exchange_frames(&mut self, frames: Vec<Vec<u8>>) -> Result<Vec<u8>, LedgerError> {
        for frame in frames {
            self.link.write(&frame).await?;
        }
        let mut response = BleResponse::default();
        loop {
            let frame = self.link.read().await?;
            if let Some(bytes) = response.push(&frame)? {
                return Ok(bytes);
            }
        }
    }
}

impl<I: PacketIo> ApduTransport for BleChannel<I> {
    async fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError> {
        if !self.ready {
            return Err(LedgerError::Disconnected);
        }
        let frames = BleFrames::encode(command, self.frame_size)?;
        // Leave the link unusable if this future is cancelled or a response is incomplete.
        self.ready = false;
        let result = timeout(self.timeout, self.exchange_frames(frames))
            .await
            .map_err(|_| LedgerError::Timeout)?;
        if result.is_ok() {
            self.ready = true;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct MockIo {
        responses: VecDeque<Result<Vec<u8>, LedgerError>>,
        writes: Vec<Vec<u8>>,
    }

    impl MockIo {
        fn new(responses: Vec<Result<Vec<u8>, LedgerError>>) -> Self {
            Self {
                responses: responses.into(),
                writes: Vec::new(),
            }
        }
    }

    impl PacketIo for MockIo {
        async fn write(&mut self, bytes: &[u8]) -> Result<(), LedgerError> {
            self.writes.push(bytes.to_vec());
            Ok(())
        }
        async fn read(&mut self) -> Result<Vec<u8>, LedgerError> {
            match self.responses.pop_front() {
                Some(response) => response,
                None => std::future::pending().await,
            }
        }
        async fn disconnect(&mut self) -> Result<(), LedgerError> {
            Ok(())
        }
        fn mtu(&self) -> usize {
            20
        }
    }

    #[tokio::test]
    async fn negotiates_then_exchanges_apdu_with_platform_frame_limit() {
        let io = MockIo::new(vec![
            Ok(vec![8, 0, 0, 0, 1, 244]),
            Ok(vec![5, 0, 0, 0, 2, 0x90, 0]),
        ]);
        let mut channel = BleChannel::new(io, Duration::from_secs(1)).await.unwrap();
        assert_eq!(channel.frame_size, 20);
        assert_eq!(
            channel.exchange(&[0xe0, 2, 0, 0, 0]).await.unwrap(),
            vec![0x90, 0]
        );
        assert_eq!(
            channel.link.writes,
            vec![vec![8, 0, 0, 0, 0], vec![5, 0, 0, 0, 5, 0xe0, 2, 0, 0, 0]]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_cancellation_and_malformed_response_retire_connection() {
        for cancel in [false, true] {
            let io = MockIo::new(vec![Ok(vec![8, 0, 0, 0, 1, 20])]);
            let mut channel = BleChannel::new(io, Duration::from_secs(2)).await.unwrap();
            if cancel {
                assert!(
                    timeout(Duration::from_secs(1), channel.exchange(&[1]))
                        .await
                        .is_err()
                );
            } else {
                assert!(matches!(
                    channel.exchange(&[1]).await,
                    Err(LedgerError::Timeout)
                ));
            }
            channel
                .link
                .responses
                .push_back(Ok(vec![5, 0, 0, 0, 2, 0x90, 0]));
            assert!(matches!(
                channel.exchange(&[2]).await,
                Err(LedgerError::Disconnected)
            ));
            assert_eq!(channel.link.writes.len(), 2);
        }
        for response in [Ok(vec![5, 0, 9]), Err(LedgerError::Disconnected)] {
            let io = MockIo::new(vec![Ok(vec![8, 0, 0, 0, 1, 20]), response]);
            let mut channel = BleChannel::new(io, Duration::from_secs(1)).await.unwrap();
            assert!(channel.exchange(&[1]).await.is_err());
            assert!(matches!(
                channel.exchange(&[2]).await,
                Err(LedgerError::Disconnected)
            ));
        }
    }
}
