use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use futures::StreamExt;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{BleError, BleProfile, BleResult, DeviceInfo};

pub struct BleSession {
    peripheral: Peripheral,
    profile: BleProfile,
    device: DeviceInfo,
    write_char: Characteristic,
    notify_char: Characteristic,
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
        let write_char = characteristics
            .iter()
            .find(|c| c.uuid == profile.write_uuid)
            .cloned()
            .ok_or_else(|| BleError::missing("write", profile))?;
        let notify_char = characteristics
            .iter()
            .find(|c| c.uuid == profile.notify_uuid)
            .cloned()
            .ok_or_else(|| BleError::missing("notify", profile))?;

        // Match Suite's BLE connect behavior: perform a write-with-response probe
        // so CoreBluetooth can surface pairing/auth failures before THP begins.
        peripheral
            .write(&write_char, b"Proof of connection", WriteType::WithResponse)
            .await?;

        peripheral.subscribe(&notify_char).await?;

        let mut notifications = peripheral.notifications().await?;
        let (tx, rx) = mpsc::channel(64);
        let notify_task = tokio::spawn(async move {
            while let Some(event) = notifications.next().await {
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
        self.peripheral.disconnect().await?;
        Ok(())
    }

    pub async fn write(&mut self, chunk: &[u8]) -> anyhow::Result<()> {
        self.peripheral
            .write(&self.write_char, chunk, WriteType::WithoutResponse)
            .await?;
        Ok(())
    }

    pub async fn read(&mut self) -> anyhow::Result<Vec<u8>> {
        match self.receiver.recv().await {
            Some(data) => Ok(data),
            None => Err(BleError::NotificationStreamClosed.into()),
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
