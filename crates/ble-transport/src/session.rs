use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
#[cfg(not(target_os = "android"))]
use futures::StreamExt;
use tokio::time::{self, Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;
use uuid::Uuid;

use crate::{BleError, BleProfile, BleResult, DeviceInfo};

#[cfg(not(target_os = "android"))]
const PROOF_OF_CONNECTION: &[u8] = b"Proof of connection";

fn redact_device_id(device_id: &str) -> String {
    let chars: Vec<char> = device_id.chars().collect();
    if chars.is_empty() {
        return "<redacted>".to_string();
    }
    let start = chars.len().saturating_sub(6);
    format!("...{}", chars[start..].iter().collect::<String>())
}

pub struct BleSession {
    peripheral: Peripheral,
    profile: BleProfile,
    device: DeviceInfo,
    write_char: Characteristic,
    notify_char: Characteristic,
    push_char: Option<Characteristic>,
    receiver: mpsc::Receiver<BleResult<Vec<u8>>>,
    notify_task: JoinHandle<()>,
    mtu: usize,
}

impl BleSession {
    pub async fn new(
        peripheral: Peripheral,
        profile: BleProfile,
        device: DeviceInfo,
    ) -> BleResult<Self> {
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }
        peripheral.discover_services().await?;

        let characteristics = peripheral.characteristics();
        let redacted_device_id = redact_device_id(&device.id);
        debug!(
            device_id = %redacted_device_id,
            profile = profile.id,
            characteristic_count = characteristics.len(),
            "BLE discovered characteristics"
        );

        let write_char =
            find_characteristic(&characteristics, profile.service_uuid, profile.write_uuid)
                .ok_or_else(|| BleError::missing("write", profile))?;
        let notify_char =
            find_characteristic(&characteristics, profile.service_uuid, profile.notify_uuid)
                .ok_or_else(|| BleError::missing("notify", profile))?;
        let push_char = match profile.push_uuid {
            Some(push_uuid) => Some(
                find_characteristic(&characteristics, profile.service_uuid, push_uuid)
                    .ok_or_else(|| BleError::missing("push", profile))?,
            ),
            None => None,
        };

        debug!(
            device_id = %redacted_device_id,
            profile = profile.id,
            write_uuid = %write_char.uuid,
            write_props = ?write_char.properties,
            notify_uuid = %notify_char.uuid,
            notify_props = ?notify_char.properties,
            push_uuid = ?push_char.as_ref().map(|c| c.uuid),
            push_props = ?push_char.as_ref().map(|c| c.properties),
            "BLE characteristics resolved"
        );

        #[cfg(not(target_os = "android"))]
        {
            peripheral
                .write(&write_char, PROOF_OF_CONNECTION, WriteType::WithResponse)
                .await?;
        }

        peripheral.subscribe(&notify_char).await?;
        if let Some(push_char) = &push_char {
            peripheral.subscribe(push_char).await?;
        }

        #[cfg(target_os = "android")]
        let (rx, notify_task) = {
            let peripheral = peripheral.clone();
            let notify_char = notify_char.clone();
            let (tx, rx) = mpsc::channel::<BleResult<Vec<u8>>>(64);
            // Keep the JNI read future alive across caller timeouts; channel receives are cancel-safe.
            let notify_task = tokio::spawn(async move {
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
            (rx, notify_task)
        };

        #[cfg(not(target_os = "android"))]
        let (rx, notify_task) = {
            let mut notifications = peripheral.notifications().await?;
            let (tx, rx) = mpsc::channel::<BleResult<Vec<u8>>>(64);
            let notify_task = tokio::spawn(async move {
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
            (rx, notify_task)
        };

        let mtu_hint = profile.mtu_hint.map(|m| m as usize).unwrap_or(244);
        #[cfg(target_os = "android")]
        let mtu = {
            let negotiated_payload = peripheral.mtu().saturating_sub(3) as usize;
            let safe_cap = std::env::var("HWCORE_BLE_ANDROID_TX_MTU")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(244)
                .max(1);
            let selected = mtu_hint.min(safe_cap).min(negotiated_payload.max(1));
            debug!(
                mtu_hint,
                negotiated_payload,
                safe_cap,
                selected,
                "BLE TX mtu selected (android conservative mode)"
            );
            selected
        };
        #[cfg(not(target_os = "android"))]
        let mtu = mtu_hint;

        Ok(Self {
            peripheral,
            profile,
            device,
            write_char,
            notify_char,
            push_char,
            receiver: rx,
            notify_task,
            mtu,
        })
    }

    pub fn info(&self) -> &DeviceInfo {
        &self.device
    }

    pub fn profile(&self) -> BleProfile {
        self.profile
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn into_link(self) -> BleLink {
        BleLink {
            peripheral: self.peripheral,
            write_char: self.write_char,
            notify_char: self.notify_char,
            push_char: self.push_char,
            receiver: self.receiver,
            notify_task: self.notify_task,
            mtu: self.mtu,
        }
    }

    pub fn into_parts(self) -> (DeviceInfo, BleLink) {
        let info = self.device.clone();
        (info, self.into_link())
    }
}

pub struct BleLink {
    peripheral: Peripheral,
    write_char: Characteristic,
    notify_char: Characteristic,
    push_char: Option<Characteristic>,
    receiver: mpsc::Receiver<BleResult<Vec<u8>>>,
    notify_task: JoinHandle<()>,
    mtu: usize,
}

impl BleLink {
    pub async fn disconnect(&mut self) -> BleResult<()> {
        if !self.peripheral.is_connected().await? {
            return Ok(());
        }
        self.receiver.close();
        self.notify_task.abort();
        let _ = (&mut self.notify_task).await;
        self.peripheral.unsubscribe(&self.notify_char).await?;
        if let Some(push_char) = &self.push_char {
            self.peripheral.unsubscribe(push_char).await?;
        }
        self.peripheral.disconnect().await?;
        Ok(())
    }

    pub async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        let write_type = WriteType::WithoutResponse;

        debug!(
            bytes = chunk.len(),
            write_type = ?write_type,
            "BLE write chunk"
        );
        self.peripheral
            .write(&self.write_char, chunk, write_type)
            .await?;
        debug!(bytes = chunk.len(), write_type = ?write_type, "BLE write chunk complete");
        Ok(())
    }

    pub async fn read(&mut self) -> anyhow::Result<Vec<u8>> {
        let data = receive_notification(&mut self.receiver).await?;
        debug!(bytes = data.len(), source = "notify", "BLE read chunk");
        Ok(data)
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl Drop for BleLink {
    fn drop(&mut self) {
        self.notify_task.abort();
    }
}

pub struct BleBackend {
    link: BleLink,
}

impl BleBackend {
    pub fn new(link: BleLink) -> Self {
        Self { link }
    }

    pub fn link_mut(&mut self) -> &mut BleLink {
        &mut self.link
    }
}

impl BleBackend {
    pub async fn abort(&mut self) -> BleResult<()> {
        self.link.disconnect().await
    }
}

async fn receive_notification(
    receiver: &mut mpsc::Receiver<BleResult<Vec<u8>>>,
) -> BleResult<Vec<u8>> {
    loop {
        match time::timeout(Duration::from_millis(250), receiver.recv()).await {
            Ok(Some(result)) => return result,
            Ok(None) => return Err(BleError::NotificationStreamClosed),
            Err(_) => {}
        }
    }
}

fn find_characteristic(
    characteristics: &std::collections::BTreeSet<Characteristic>,
    service_uuid: Uuid,
    uuid: Uuid,
) -> Option<Characteristic> {
    characteristics
        .iter()
        .find(|c| c.service_uuid == service_uuid && c.uuid == uuid)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn timed_out_consumer_keeps_persistent_notification_reader() {
        let (tx, mut rx) = mpsc::channel::<BleResult<Vec<u8>>>(1);
        let (started_tx, started_rx) = oneshot::channel();
        let (deliver_tx, deliver_rx) = oneshot::channel();
        let producer = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            deliver_rx.await.unwrap();
            tx.send(Ok(vec![0x42])).await.unwrap();
        });

        started_rx.await.unwrap();
        assert!(
            time::timeout(Duration::from_millis(1), receive_notification(&mut rx))
                .await
                .is_err()
        );
        deliver_tx.send(()).unwrap();

        assert_eq!(receive_notification(&mut rx).await.unwrap(), vec![0x42]);
        producer.await.unwrap();
    }
}
