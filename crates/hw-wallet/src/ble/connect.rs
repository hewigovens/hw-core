use std::sync::Arc;
use std::time::{Duration, Instant};

use ble_transport::{BleError, BleManager, BleProfile, BleSession, DiscoveredDevice};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::{HostConfig, ThpWorkflow, ThpWorkflowError};

use super::session_bootstrap::{BootstrapTarget, SessionBootstrap, SessionBootstrapOptions};
use super::session_state::SessionPhase;
use crate::error::{WalletError, WalletResult};

const SCAN_WINDOW: Duration = Duration::from_secs(3);

pub async fn connect_trezor_device(
    device: DiscoveredDevice,
    profile: BleProfile,
) -> WalletResult<BleSession> {
    device
        .connect(profile)
        .await
        .map_err(WalletError::from_connect_error)
}

pub async fn connect_and_bootstrap_session(
    device: DiscoveredDevice,
    profile: BleProfile,
    config: HostConfig,
    storage: Option<Arc<dyn ThpStorage>>,
    options: SessionBootstrapOptions,
) -> WalletResult<ThpWorkflow<BleBackend>> {
    let session = connect_trezor_device(device, profile).await?;
    let backend = BleBackend::from_session(session, options.thp_timeout);

    let mut workflow = if let Some(storage) = storage {
        ThpWorkflow::with_storage(backend, config, storage).await?
    } else {
        ThpWorkflow::new(backend, config)
    };

    let phase = workflow
        .advance_session_bootstrap(false, BootstrapTarget::Session, &options)
        .await?;
    match phase {
        SessionPhase::Ready => Ok(workflow),
        SessionPhase::NeedsPairingCode => Err(ThpWorkflowError::PairingInteractionRequired.into()),
        SessionPhase::NeedsChannel
        | SessionPhase::NeedsHandshake
        | SessionPhase::NeedsConnectionConfirmation
        | SessionPhase::NeedsSession => Err(ThpWorkflowError::InvalidPhase.into()),
    }
}

pub async fn scan_profile_until_match(
    manager: &BleManager,
    profile: BleProfile,
    duration: Duration,
    device_id_filter: Option<&str>,
) -> WalletResult<Vec<DiscoveredDevice>> {
    let start = Instant::now();
    let mut last_seen = Vec::new();
    while start.elapsed() < duration {
        let remaining = duration.saturating_sub(start.elapsed());
        let window = remaining.min(SCAN_WINDOW);
        let devices = manager.scan_profile(profile, window).await?;
        if devices.is_empty() {
            continue;
        }

        let Some(query) = device_id_filter else {
            return Ok(devices);
        };
        if devices
            .iter()
            .any(|device| device.info().id.contains(query))
        {
            return Ok(devices);
        }
        last_seen = devices;
    }

    Ok(last_seen)
}

impl WalletError {
    fn from_connect_error(error: BleError) -> Self {
        // btleplug surfaces this CoreBluetooth condition only as message text.
        if error
            .to_string()
            .to_lowercase()
            .contains("peer removed pairing information")
        {
            Self::PeerRemovedPairingInfo
        } else {
            Self::Ble(error)
        }
    }
}
