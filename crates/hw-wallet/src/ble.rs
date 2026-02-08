use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ble_transport::{BleError, BleManager, BleProfile, BleSession, DiscoveredDevice};
use tokio::time::{sleep, timeout};
use tracing::debug;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::{
    BackendError, HostConfig, Phase, ThpBackend, ThpWorkflow, ThpWorkflowError,
};

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
    let session = BleSession::new(peripheral, profile, info)
        .await
        .map_err(|err| {
            if is_peer_removed_pairing_info(&err) {
                WalletError::PeerRemovedPairingInfo
            } else {
                WalletError::Ble(err)
            }
        })?;
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

pub const CREATE_CHANNEL_ATTEMPTS: usize = 3;
pub const HANDSHAKE_ATTEMPTS: usize = 2;
pub const CREATE_SESSION_ATTEMPTS: usize = 3;
pub const RETRY_DELAY: Duration = Duration::from_millis(800);
const CREATE_CHANNEL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone)]
pub struct ReadyWorkflowOptions {
    pub thp_timeout: Duration,
    pub try_to_unlock: bool,
    pub passphrase: Option<String>,
    pub on_device: bool,
    pub derive_cardano: bool,
}

impl Default for ReadyWorkflowOptions {
    fn default() -> Self {
        Self {
            thp_timeout: Duration::from_secs(60),
            try_to_unlock: false,
            passphrase: None,
            on_device: false,
            derive_cardano: false,
        }
    }
}

pub async fn connect_and_prepare_workflow(
    device: DiscoveredDevice,
    profile: BleProfile,
    config: HostConfig,
    storage: Option<Arc<dyn ThpStorage>>,
    options: ReadyWorkflowOptions,
) -> WalletResult<ThpWorkflow<BleBackend>> {
    let session = connect_trezor_device(device, profile).await?;
    let backend = backend_from_session(session, options.thp_timeout);

    let mut workflow = if let Some(storage) = storage {
        workflow_with_storage(backend, config, storage).await?
    } else {
        workflow(backend, config)
    };

    prepare_ready_workflow(&mut workflow, &options).await?;
    Ok(workflow)
}

pub async fn prepare_ready_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    options: &ReadyWorkflowOptions,
) -> WalletResult<()>
where
    B: ThpBackend + Send,
{
    establish_authenticated_phase(workflow, options.try_to_unlock).await?;
    create_session_with_retry(
        workflow,
        options.passphrase.clone(),
        options.on_device,
        options.derive_cardano,
        CREATE_SESSION_ATTEMPTS,
        RETRY_DELAY,
    )
    .await?;
    Ok(())
}

pub async fn establish_authenticated_phase<B>(
    workflow: &mut ThpWorkflow<B>,
    try_to_unlock: bool,
) -> WalletResult<()>
where
    B: ThpBackend + Send,
{
    create_channel_with_retry(workflow, CREATE_CHANNEL_ATTEMPTS, RETRY_DELAY).await?;
    handshake_with_retry(workflow, try_to_unlock, HANDSHAKE_ATTEMPTS, RETRY_DELAY).await?;

    match workflow.state().phase() {
        Phase::Paired => Ok(()),
        Phase::Pairing => {
            if workflow.state().is_paired() {
                workflow.pairing(None).await.map_err(WalletError::from)?;
                Ok(())
            } else {
                Err(WalletError::Workflow(
                    ThpWorkflowError::PairingInteractionRequired,
                ))
            }
        }
        _ => Err(WalletError::Workflow(ThpWorkflowError::InvalidPhase)),
    }
}

pub async fn create_channel_with_retry<B>(
    workflow: &mut ThpWorkflow<B>,
    attempts: usize,
    retry_delay: Duration,
) -> WalletResult<usize>
where
    B: ThpBackend + Send,
{
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match timeout(CREATE_CHANNEL_ATTEMPT_TIMEOUT, workflow.create_channel()).await {
            Err(_) if attempt < attempts => {
                debug!(
                    "create-channel timed out after {:?} on attempt {}; retrying after {:?}",
                    CREATE_CHANNEL_ATTEMPT_TIMEOUT, attempt, retry_delay
                );
                sleep(retry_delay).await;
            }
            Err(_) => {
                return Err(WalletError::Workflow(ThpWorkflowError::Backend(
                    BackendError::Transport(format!(
                        "timeout waiting for BLE response (create-channel attempt timeout {:?})",
                        CREATE_CHANNEL_ATTEMPT_TIMEOUT
                    )),
                )));
            }
            Ok(Ok(())) => {
                return Ok(attempt);
            }
            Ok(Err(err)) if is_transport_timeout(&err) && attempt < attempts => {
                debug!(
                    "create-channel timed out on attempt {}; retrying after {:?}",
                    attempt, retry_delay
                );
                sleep(retry_delay).await;
            }
            Ok(Err(err)) => return Err(err.into()),
        }
    }

    unreachable!("attempts is always >= 1")
}

pub async fn handshake_with_retry<B>(
    workflow: &mut ThpWorkflow<B>,
    try_to_unlock: bool,
    attempts: usize,
    retry_delay: Duration,
) -> WalletResult<usize>
where
    B: ThpBackend + Send,
{
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match workflow.handshake(try_to_unlock).await {
            Ok(()) => return Ok(attempt),
            Err(err) if is_retryable_handshake_error(&err) && attempt < attempts => {
                debug!(
                    "handshake failed with transient device state on attempt {}; retrying after {:?}",
                    attempt, retry_delay
                );
                sleep(retry_delay).await;
                create_channel_with_retry(workflow, 3, retry_delay).await?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    unreachable!("attempts is always >= 1")
}

pub async fn create_session_with_retry<B>(
    workflow: &mut ThpWorkflow<B>,
    passphrase: Option<String>,
    on_device: bool,
    derive_cardano: bool,
    attempts: usize,
    retry_delay: Duration,
) -> WalletResult<usize>
where
    B: ThpBackend + Send,
{
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        match workflow
            .create_session(passphrase.clone(), on_device, derive_cardano)
            .await
        {
            Ok(()) => return Ok(attempt),
            Err(err) if is_retryable_session_error(&err) && attempt < attempts => {
                debug!(
                    "create-session hit transient device state on attempt {}; retrying after {:?}",
                    attempt, retry_delay
                );
                sleep(retry_delay).await;
            }
            Err(err) => return Err(normalize_session_error(err)),
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

fn is_retryable_handshake_error(error: &ThpWorkflowError) -> bool {
    match error {
        ThpWorkflowError::Backend(BackendError::Device(message)) => {
            message.contains("error code 5")
                || message.contains("ThpTransportBusy")
                || message.contains("transport busy")
        }
        _ => false,
    }
}

fn is_retryable_session_error(error: &ThpWorkflowError) -> bool {
    match error {
        ThpWorkflowError::Backend(BackendError::Device(message)) => {
            message.contains("error code 5")
                || message.contains("error code 99")
                || message.contains("ThpTransportBusy")
                || message.contains("transport busy")
                || message.contains("session requires connection confirmation")
        }
        _ => false,
    }
}

fn normalize_session_error(error: ThpWorkflowError) -> WalletError {
    match error {
        ThpWorkflowError::Backend(BackendError::Device(message))
            if message.contains("error code 99") =>
        {
            WalletError::Workflow(ThpWorkflowError::Backend(BackendError::Device(
                "device reported firmware busy (error code 99). Ensure the Trezor screen is unlocked and idle, then retry.".into(),
            )))
        }
        ThpWorkflowError::Backend(BackendError::Device(message))
            if message.contains("error code 5") =>
        {
            WalletError::Workflow(ThpWorkflowError::Backend(BackendError::Device(
                "device is not ready yet (error code 5). Wait for the device prompt/unlock and retry.".into(),
            )))
        }
        other => WalletError::Workflow(other),
    }
}

pub async fn scan_profile_until_match(
    manager: &BleManager,
    profile: BleProfile,
    duration: Duration,
    device_id_filter: Option<&str>,
) -> WalletResult<Vec<DiscoveredDevice>> {
    const SCAN_WINDOW: Duration = Duration::from_secs(3);

    let start = Instant::now();
    let mut last_seen = Vec::new();
    while start.elapsed() < duration {
        let remaining = duration.saturating_sub(start.elapsed());
        let window = remaining.min(SCAN_WINDOW);
        let devices = scan_profile(manager, profile, window).await?;
        if devices.is_empty() {
            continue;
        }

        if let Some(query) = device_id_filter {
            if devices.iter().any(|device| device_matches(device, query)) {
                return Ok(devices);
            }
            last_seen = devices;
            continue;
        }

        return Ok(devices);
    }

    Ok(last_seen)
}

fn device_matches(device: &DiscoveredDevice, query: &str) -> bool {
    let id = &device.info().id;
    id == query || id.contains(query)
}

fn is_peer_removed_pairing_info(error: &BleError) -> bool {
    error
        .to_string()
        .to_lowercase()
        .contains("peer removed pairing information")
}
