use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
#[cfg(not(target_os = "android"))]
use futures::StreamExt;
#[cfg(not(target_os = "android"))]
use tokio::time::{self, Duration};
#[cfg(not(target_os = "android"))]
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
    #[cfg(not(target_os = "android"))]
    receiver: mpsc::Receiver<Vec<u8>>,
    #[cfg(not(target_os = "android"))]
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
            // Keep iOS/macOS behavior where a small probe write helps surface
            // pairing/auth failures before THP starts.
            peripheral
                .write(&write_char, PROOF_OF_CONNECTION, WriteType::WithResponse)
                .await?;
        }

        peripheral.subscribe(&notify_char).await?;
        if let Some(push_char) = &push_char {
            peripheral.subscribe(push_char).await?;
        }

        #[cfg(not(target_os = "android"))]
        let (rx, notify_task) = {
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
                debug!("BLE notification stream ended");
            });
            (rx, notify_task)
        };

        let mtu_hint = profile.mtu_hint.map(|m| m as usize).unwrap_or(244);
        #[cfg(target_os = "android")]
        let mtu = {
            // Android defaults to 23-byte ATT MTU unless requestMtu succeeds.
            // We request MTU 247 in the Droidplug Java shim; keep this cap overridable.
            let safe_cap = std::env::var("HWCORE_BLE_ANDROID_TX_MTU")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(244)
                .max(1);
            let selected = mtu_hint.min(safe_cap);
            debug!(
                mtu_hint,
                safe_cap, selected, "BLE TX mtu selected (android conservative mode)"
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
            #[cfg(not(target_os = "android"))]
            receiver: rx,
            #[cfg(not(target_os = "android"))]
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
            #[cfg(not(target_os = "android"))]
            receiver: self.receiver,
            #[cfg(not(target_os = "android"))]
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
    #[cfg(not(target_os = "android"))]
    receiver: mpsc::Receiver<Vec<u8>>,
    #[cfg(not(target_os = "android"))]
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
        #[cfg(target_os = "android")]
        {
            loop {
                let data = self.peripheral.read(&self.notify_char).await?;
                if !data.is_empty() {
                    debug!(bytes = data.len(), source = "read-notify", "BLE read chunk");
                    return Ok(data);
                }
            }
        }

        #[cfg(not(target_os = "android"))]
        loop {
            match time::timeout(Duration::from_millis(250), self.receiver.recv()).await {
                Ok(Some(data)) => {
                    debug!(bytes = data.len(), source = "notify", "BLE read chunk");
                    return Ok(data);
                }
                Ok(None) => return Err(BleError::NotificationStreamClosed.into()),
                Err(_) => {}
            }
        }
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl Drop for BleLink {
    #[cfg(not(target_os = "android"))]
    fn drop(&mut self) {
        self.notify_task.abort();
    }

    #[cfg(target_os = "android")]
    fn drop(&mut self) {}
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
