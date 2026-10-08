use btleplug::api::{Characteristic, Peripheral as _};
use btleplug::platform::Peripheral;
#[cfg(not(target_os = "android"))]
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration};
use tracing::debug;

use crate::{BleError, BleResult};

type Notification = BleResult<Vec<u8>>;

pub(crate) struct Notifications {
    receiver: mpsc::Receiver<Notification>,
    task: JoinHandle<()>,
}

impl Notifications {
    #[cfg(target_os = "android")]
    pub(crate) async fn spawn(
        peripheral: &Peripheral,
        notify_char: &Characteristic,
    ) -> BleResult<Self> {
        let peripheral = peripheral.clone();
        let notify_char = notify_char.clone();
        let (tx, receiver) = mpsc::channel::<Notification>(64);
        // Keep the JNI read future alive across caller timeouts; channel receives are cancel-safe.
        let task = tokio::spawn(async move {
            while !tx.is_closed() {
                let read_result = peripheral.read(&notify_char).await;
                if tx.is_closed() {
                    break;
                }
                match read_result {
                    Ok(data) if data.is_empty() => {}
                    Ok(data) => {
                        debug!(
                            characteristic = %notify_char.uuid,
                            bytes = data.len(),
                            "BLE notification received"
                        );
                        if tx.send(Ok(data)).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx.send(Err(err.into())).await;
                        break;
                    }
                }
            }
            debug!("BLE notification reader ended");
        });
        Ok(Self { receiver, task })
    }

    #[cfg(not(target_os = "android"))]
    pub(crate) async fn spawn(
        peripheral: &Peripheral,
        _notify_char: &Characteristic,
    ) -> BleResult<Self> {
        let mut notifications = peripheral.notifications().await?;
        let (tx, receiver) = mpsc::channel::<Notification>(64);
        let task = tokio::spawn(async move {
            while let Some(event) = notifications.next().await {
                debug!(
                    characteristic = %event.uuid,
                    bytes = event.value.len(),
                    "BLE notification received"
                );
                if tx.send(Ok(event.value)).await.is_err() {
                    break;
                }
            }
            debug!("BLE notification stream ended");
        });
        Ok(Self { receiver, task })
    }

    pub(crate) async fn recv(&mut self) -> Notification {
        loop {
            match time::timeout(Duration::from_millis(250), self.receiver.recv()).await {
                Ok(Some(result)) => return result,
                Ok(None) => return Err(BleError::NotificationStreamClosed),
                Err(_) => {}
            }
        }
    }

    pub(crate) async fn stop(&mut self) {
        self.receiver.close();
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for Notifications {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn timed_out_consumer_keeps_persistent_notification_reader() {
        let (tx, receiver) = mpsc::channel::<Notification>(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (deliver_tx, deliver_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            deliver_rx.await.unwrap();
            tx.send(Ok(vec![0x42])).await.unwrap();
        });
        let mut notifications = Notifications { receiver, task };

        started_rx.await.unwrap();
        assert!(
            time::timeout(Duration::from_millis(1), notifications.recv())
                .await
                .is_err()
        );
        deliver_tx.send(()).unwrap();

        assert_eq!(notifications.recv().await.unwrap(), vec![0x42]);
    }
}
