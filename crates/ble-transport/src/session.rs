use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use tokio::time::{self, Duration};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::debug;
use uuid::Uuid;

use crate::{BleError, BleProfile, BleResult, DeviceInfo};

const PROOF_OF_CONNECTION: &[u8] = b"Proof of connection";

pub struct BleSession {
    peripheral: Peripheral,
    profile: BleProfile,
    device: DeviceInfo,
    write_char: Characteristic,
    notify_char: Characteristic,
    push_char: Option<Characteristic>,
    receiver: mpsc::Receiver<Vec<u8>>,
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
        let discovered: Vec<String> = characteristics
            .iter()
            .map(|c| format!("{}/{:?}/{:?}", c.service_uuid, c.uuid, c.properties))
            .collect();
        debug!(
            device_id = %device.id,
            profile = profile.id,
            characteristics = ?discovered,
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
            device_id = %device.id,
            profile = profile.id,
            write_uuid = %write_char.uuid,
            write_props = ?write_char.properties,
            notify_uuid = %notify_char.uuid,
            notify_props = ?notify_char.properties,
            push_uuid = ?push_char.as_ref().map(|c| c.uuid),
            push_props = ?push_char.as_ref().map(|c| c.properties),
            "BLE characteristics resolved"
        );

        // Match Suite's BLE connect behavior: perform a write-with-response probe
        // so CoreBluetooth can surface pairing/auth failures before THP begins.
        peripheral
            .write(&write_char, PROOF_OF_CONNECTION, WriteType::WithResponse)
            .await?;

        peripheral.subscribe(&notify_char).await?;
        if let Some(push_char) = &push_char {
            peripheral.subscribe(push_char).await?;
        }
        let mut notifications = peripheral.notifications().await?;

        let (tx, rx) = mpsc::channel(64);
        let notify_task = tokio::spawn(async move {
            while let Some(event) = notifications.next().await {
                debug!(
                    characteristic = %event.uuid,
                    bytes = event.value.len(),
                    "BLE notification received"
                );
                if tx.send(event.value).await.is_err() {
                    break;
                }
            }
        });

        let mtu = profile.mtu_hint.map(|m| m as usize).unwrap_or(244);

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
    receiver: mpsc::Receiver<Vec<u8>>,
    notify_task: JoinHandle<()>,
    mtu: usize,
}

impl BleLink {
    pub async fn disconnect(&mut self) -> BleResult<()> {
        if !self.peripheral.is_connected().await? {
            return Ok(());
        }
        self.peripheral.unsubscribe(&self.notify_char).await?;
        if let Some(push_char) = &self.push_char {
            self.peripheral.unsubscribe(push_char).await?;
        }
        self.peripheral.disconnect().await?;
        Ok(())
    }

    pub async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        debug!(
            bytes = chunk.len(),
            write_type = "without-response",
            "BLE write chunk"
        );
        self.peripheral
            .write(&self.write_char, chunk, WriteType::WithoutResponse)
            .await?;
        Ok(())
    }

    pub async fn read(&mut self) -> anyhow::Result<Vec<u8>> {
        loop {
            match time::timeout(Duration::from_millis(250), self.receiver.recv()).await {
                Ok(Some(data)) => {
                    debug!(bytes = data.len(), source = "notify", "BLE read chunk");
                    return Ok(data);
                }
                Ok(None) => return Err(BleError::NotificationStreamClosed.into()),
                Err(_) => {}
            }

            match self.peripheral.read(&self.notify_char).await {
                Ok(data) if !data.is_empty() => {
                    debug!(bytes = data.len(), source = "read-notify", "BLE read chunk");
                    return Ok(data);
                }
                Ok(_) => {}
                Err(err) => {
                    debug!(error = %err, source = "read-notify", "BLE direct read failed");
                }
            }

            if let Some(push_char) = &self.push_char {
                match self.peripheral.read(push_char).await {
                    Ok(data) if !data.is_empty() => {
                        debug!(bytes = data.len(), source = "read-push", "BLE read chunk");
                        return Ok(data);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        debug!(error = %err, source = "read-push", "BLE direct read failed");
                    }
                }
            }
        }
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
