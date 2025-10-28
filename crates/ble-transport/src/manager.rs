use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use btleplug::api::{
    Central, CentralEvent, CentralState, Manager as _, Peripheral as _, ScanFilter,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use futures::stream::Stream;
use futures::StreamExt;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time;
use uuid::Uuid;

use crate::profile::DeviceInfo;
use crate::{BleError, BleProfile, BleResult};

pub struct BleManager {
    adapter: Adapter,
}

impl BleManager {
    pub async fn new() -> BleResult<Self> {
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or(BleError::AdapterUnavailable)?;
        Ok(Self { adapter })
    }

    pub async fn scan_profiles(
        &self,
        profiles: &[BleProfile],
        duration: Duration,
    ) -> BleResult<Vec<DiscoveredDevice>> {
        let services: Vec<Uuid> = profiles.iter().map(|p| p.service_uuid).collect();
        let filter = ScanFilter {
            services: services.clone(),
        };

        self.adapter.start_scan(filter).await?;
        time::sleep(duration).await;

        let peripherals = self.adapter.peripherals().await?;
        let mut devices = Vec::new();
        for peripheral in peripherals {
            if let Some(info) = fetch_device_info(&peripheral).await? {
                if services.is_empty() || info.services.iter().any(|uuid| services.contains(uuid)) {
                    devices.push(DiscoveredDevice { info, peripheral });
                }
            }
        }
        self.adapter.stop_scan().await?;
        Ok(devices)
    }

    pub async fn scan_profile(
        &self,
        profile: BleProfile,
        duration: Duration,
    ) -> BleResult<Vec<DiscoveredDevice>> {
        self.scan_profiles(&[profile], duration).await
    }

    pub async fn start_scan(
        &self,
        profiles: &[BleProfile],
        options: ScanOptions,
    ) -> BleResult<ScanHandle> {
        let mut services: HashSet<Uuid> = options.services.iter().copied().collect();
        for profile in profiles {
            services.insert(profile.service_uuid);
        }
        let services: Vec<Uuid> = services.into_iter().collect();

        let filter = ScanFilter {
            services: services.clone(),
        };

        let mut events = self.adapter.events().await?;
        self.adapter.start_scan(filter).await?;

        let (stop_tx, mut stop_rx) = oneshot::channel();
        let capacity = options.event_buffer.max(1);
        let (event_tx, event_rx) = mpsc::channel(capacity);
        let adapter = self.adapter.clone();

        let join = tokio::spawn(async move {
            let mut event_tx = event_tx;
            loop {
                select! {
                    _ = &mut stop_rx => {
                        break;
                    }
                    maybe_evt = events.next() => {
                        match maybe_evt {
                            Some(evt) => {
                                if handle_central_event(&adapter, &mut event_tx, evt).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            let _ = adapter.stop_scan().await;
        });

        Ok(ScanHandle {
            events: event_rx,
            stop_tx: Some(stop_tx),
            join: Some(join),
        })
    }
}

pub struct ScanHandle {
    events: mpsc::Receiver<ScanEvent>,
    stop_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl ScanHandle {
    pub async fn next(&mut self) -> Option<ScanEvent> {
        self.events.recv().await
    }

    pub async fn stop(mut self) -> BleResult<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        Ok(())
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

impl Stream for ScanHandle {
    type Item = ScanEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.events).poll_recv(cx)
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub services: Vec<Uuid>,
    pub event_buffer: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            services: Vec::new(),
            event_buffer: 32,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    DeviceDiscovered(DeviceInfo),
    DeviceUpdated(DeviceInfo),
    DeviceConnected(String),
    DeviceDisconnected(String),
    StateChanged(CentralState),
}

pub struct DiscoveredDevice {
    info: DeviceInfo,
    pub(crate) peripheral: Peripheral,
}

impl DiscoveredDevice {
    pub fn info(&self) -> &DeviceInfo {
        &self.info
    }

    pub fn into_parts(self) -> (DeviceInfo, Peripheral) {
        (self.info, self.peripheral)
    }
}

async fn handle_central_event(
    adapter: &Adapter,
    sender: &mut mpsc::Sender<ScanEvent>,
    event: CentralEvent,
) -> BleResult<()> {
    match event {
        CentralEvent::DeviceDiscovered(id) => {
            if let Ok(peripheral) = adapter.peripheral(&id).await {
                if let Some(info) = fetch_device_info(&peripheral).await? {
                    let _ = sender.send(ScanEvent::DeviceDiscovered(info)).await;
                }
            }
        }
        CentralEvent::DeviceUpdated(id) => {
            if let Ok(peripheral) = adapter.peripheral(&id).await {
                if let Some(info) = fetch_device_info(&peripheral).await? {
                    let _ = sender.send(ScanEvent::DeviceUpdated(info)).await;
                }
            }
        }
        CentralEvent::DeviceConnected(id) => {
            let _ = sender
                .send(ScanEvent::DeviceConnected(format!("{id:?}")))
                .await;
        }
        CentralEvent::DeviceDisconnected(id) => {
            let _ = sender
                .send(ScanEvent::DeviceDisconnected(format!("{id:?}")))
                .await;
        }
        CentralEvent::StateUpdate(state) => {
            let _ = sender.send(ScanEvent::StateChanged(state)).await;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn fetch_device_info(peripheral: &Peripheral) -> BleResult<Option<DeviceInfo>> {
    let properties = match peripheral.properties().await? {
        Some(props) => props,
        None => return Ok(None),
    };

    Ok(Some(DeviceInfo {
        id: peripheral.id().to_string(),
        name: properties.local_name.clone(),
        rssi: properties.rssi.map(|value| value as i32),
        services: properties.services.clone(),
    }))
}

pub struct ScanBuilder<'a> {
    manager: &'a BleManager,
    profiles: Vec<BleProfile>,
    options: ScanOptions,
}

impl<'a> ScanBuilder<'a> {
    pub fn new(manager: &'a BleManager, profiles: Vec<BleProfile>) -> Self {
        Self {
            manager,
            profiles,
            options: ScanOptions::default(),
        }
    }

    pub fn options(mut self, options: ScanOptions) -> Self {
        self.options = options;
        self
    }

    pub async fn start(self) -> BleResult<ScanHandle> {
        self.manager.start_scan(&self.profiles, self.options).await
    }
}
