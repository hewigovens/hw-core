use btleplug::api::{Characteristic, Peripheral as _, WriteType};
use btleplug::platform::Peripheral;
use tracing::debug;

use crate::notifications::Notifications;
use crate::{BleProfile, BleResult, DeviceInfo};

#[cfg(not(target_os = "android"))]
const PROOF_OF_CONNECTION: &[u8] = b"Proof of connection";

const DEFAULT_MTU: usize = 244;

pub struct BleLink {
    peripheral: Peripheral,
    write_char: Characteristic,
    notify_char: Characteristic,
    push_char: Option<Characteristic>,
    notifications: Notifications,
    mtu: usize,
}

impl BleLink {
    pub(crate) async fn open(
        peripheral: Peripheral,
        profile: BleProfile,
        device: &DeviceInfo,
    ) -> BleResult<Self> {
        if !peripheral.is_connected().await? {
            peripheral.connect().await?;
        }
        peripheral.discover_services().await?;

        let characteristics = peripheral.characteristics();
        let redacted_device_id = device.redacted_id();
        debug!(
            device_id = %redacted_device_id,
            profile = profile.id,
            characteristic_count = characteristics.len(),
            "BLE discovered characteristics"
        );

        let write_char = profile.characteristic(&characteristics, profile.write_uuid, "write")?;
        let notify_char =
            profile.characteristic(&characteristics, profile.notify_uuid, "notify")?;
        let push_char = profile
            .push_uuid
            .map(|uuid| profile.characteristic(&characteristics, uuid, "push"))
            .transpose()?;

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
        peripheral
            .write(&write_char, PROOF_OF_CONNECTION, WriteType::WithResponse)
            .await?;

        peripheral.subscribe(&notify_char).await?;
        if let Some(push_char) = &push_char {
            peripheral.subscribe(push_char).await?;
        }

        let notifications = Notifications::spawn(&peripheral, &notify_char).await?;
        let mtu = Self::select_mtu(&peripheral, profile);

        Ok(Self {
            peripheral,
            write_char,
            notify_char,
            push_char,
            notifications,
            mtu,
        })
    }

    #[cfg(target_os = "android")]
    fn select_mtu(peripheral: &Peripheral, profile: BleProfile) -> usize {
        let mtu_hint = Self::mtu_hint(profile);
        let negotiated_payload = peripheral.mtu().saturating_sub(3) as usize;
        let safe_cap = std::env::var("HWCORE_BLE_ANDROID_TX_MTU")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MTU)
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
    }

    #[cfg(not(target_os = "android"))]
    fn select_mtu(_peripheral: &Peripheral, profile: BleProfile) -> usize {
        Self::mtu_hint(profile)
    }

    fn mtu_hint(profile: BleProfile) -> usize {
        profile.mtu_hint.map_or(DEFAULT_MTU, usize::from)
    }

    pub async fn disconnect(&mut self) -> BleResult<()> {
        if !self.peripheral.is_connected().await? {
            return Ok(());
        }
        self.notifications.stop().await;
        self.peripheral.unsubscribe(&self.notify_char).await?;
        if let Some(push_char) = &self.push_char {
            self.peripheral.unsubscribe(push_char).await?;
        }
        self.peripheral.disconnect().await?;
        Ok(())
    }

    pub async fn write(&mut self, chunk: &[u8]) -> BleResult<()> {
        let write_type = WriteType::WithoutResponse;
        debug!(bytes = chunk.len(), write_type = ?write_type, "BLE write chunk");
        self.peripheral
            .write(&self.write_char, chunk, write_type)
            .await?;
        debug!(bytes = chunk.len(), write_type = ?write_type, "BLE write chunk complete");
        Ok(())
    }

    pub async fn read(&mut self) -> BleResult<Vec<u8>> {
        let data = self.notifications.recv().await?;
        debug!(bytes = data.len(), source = "notify", "BLE read chunk");
        Ok(data)
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}
