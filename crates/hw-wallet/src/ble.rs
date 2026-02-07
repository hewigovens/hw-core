use std::sync::Arc;
use std::time::Duration;

use ble_transport::{BleManager, BleProfile, BleSession, DiscoveredDevice};
use tokio::time::sleep;
use tracing::debug;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::{BackendError, HostConfig, ThpWorkflow, ThpWorkflowError};

use crate::error::{WalletError, WalletResult};

pub fn trezor_profile() -> WalletResult<BleProfile> {
    BleProfile::trezor_safe7().ok_or(WalletError::ProfileUnavailable)
}

pub async fn scan_profile(
    manager: &BleManager,
    profile: BleProfile,
    duration: Duration,
) -> WalletResult<Vec<DiscoveredDevice>> {
    let devices = manager.scan_profile(profile, duration).await?;
    Ok(devices)
}

pub async fn scan_trezor(
    manager: &BleManager,
    duration: Duration,
) -> WalletResult<(BleProfile, Vec<DiscoveredDevice>)> {
    let profile = trezor_profile()?;
    let devices = scan_profile(manager, profile, duration).await?;
    Ok((profile, devices))
}

pub async fn connect_trezor_device(
    device: DiscoveredDevice,
    profile: BleProfile,
) -> WalletResult<BleSession> {
    let (info, peripheral) = device.into_parts();
    let session = BleSession::new(peripheral, profile, info).await?;
    Ok(session)
}

pub fn backend_from_session(session: BleSession, thp_timeout: Duration) -> BleBackend {
    let mut backend = BleBackend::from_session(session);
    backend.set_handshake_timeout(thp_timeout);
    backend
}

pub async fn workflow_with_storage(
    backend: BleBackend,
    config: HostConfig,
    storage: Arc<dyn ThpStorage>,
) -> WalletResult<ThpWorkflow<BleBackend>> {
    Ok(ThpWorkflow::with_storage(backend, config, storage).await?)
}

pub fn workflow(backend: BleBackend, config: HostConfig) -> ThpWorkflow<BleBackend> {
    ThpWorkflow::new(backend, config)
}

pub async fn create_channel_with_retry(
    workflow: &mut ThpWorkflow<BleBackend>,
    attempts: usize,
    retry_delay: Duration,
) -> WalletResult<usize> {
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match workflow.create_channel().await {
            Ok(_) => {
                return Ok(attempt);
            }
            Err(err) if is_transport_timeout(&err) && attempt < attempts => {
                debug!(
                    "create-channel timed out on attempt {}; retrying after {:?}",
                    attempt, retry_delay
                );
                sleep(retry_delay).await;
            }
            Err(err) => return Err(err.into()),
        }
    }

    unreachable!("attempts is always >= 1")
}

fn is_transport_timeout(error: &ThpWorkflowError) -> bool {
    match error {
        ThpWorkflowError::Backend(BackendError::Transport(msg)) => {
            msg.contains("timeout waiting for BLE response")
        }
        _ => false,
    }
}
