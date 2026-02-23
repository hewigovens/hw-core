use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ble_transport::{BleError, BleManager, BleProfile, BleSession, DiscoveredDevice};
use tokio::time::{sleep, timeout};
use tracing::debug;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::storage::ThpStorage;
use trezor_connect::thp::{
    BackendError, HostConfig, Phase, ThpBackend, ThpState, ThpWorkflow, ThpWorkflowError,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRetryPolicy {
    pub create_channel_attempts: u32,
    pub handshake_attempts: u32,
    pub create_session_attempts: u32,
    pub retry_delay_ms: u64,
}

impl Default for SessionRetryPolicy {
    fn default() -> Self {
        Self {
            create_channel_attempts: CREATE_CHANNEL_ATTEMPTS as u32,
            handshake_attempts: HANDSHAKE_ATTEMPTS as u32,
            create_session_attempts: CREATE_SESSION_ATTEMPTS as u32,
            retry_delay_ms: RETRY_DELAY.as_millis() as u64,
        }
    }
}

impl SessionRetryPolicy {
    pub fn retry_delay(&self) -> Duration {
        Duration::from_millis(self.retry_delay_ms.max(1))
    }

    pub fn create_channel_attempts(&self) -> usize {
        self.create_channel_attempts.max(1) as usize
    }

    pub fn handshake_attempts(&self) -> usize {
        self.handshake_attempts.max(1) as usize
    }

    pub fn create_session_attempts(&self) -> usize {
        self.create_session_attempts.max(1) as usize
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionPhase {
    NeedsChannel,
    NeedsHandshake,
    NeedsPairingCode,
    NeedsConnectionConfirmation,
    NeedsSession,
    Ready,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub can_pair_only: bool,
    pub can_connect: bool,
    pub can_get_address: bool,
    pub can_sign_tx: bool,
    pub requires_pairing_code: bool,
    pub prompt_message: Option<String>,
}

pub fn session_phase(state: &ThpState, session_ready: bool) -> SessionPhase {
    if session_ready {
        return SessionPhase::Ready;
    }

    match state.phase() {
        Phase::Handshake => {
            if state.handshake_cache().is_some() {
                SessionPhase::NeedsHandshake
            } else {
                SessionPhase::NeedsChannel
            }
        }
        Phase::Pairing => {
            if state.is_paired() {
                SessionPhase::NeedsConnectionConfirmation
            } else {
                SessionPhase::NeedsPairingCode
            }
        }
        Phase::Paired => SessionPhase::NeedsSession,
    }
}

pub fn session_state(phase: SessionPhase, prompt_message: Option<String>) -> SessionState {
    SessionState {
        phase,
        can_pair_only: !matches!(phase, SessionPhase::Ready),
        can_connect: !matches!(phase, SessionPhase::Ready),
        can_get_address: matches!(phase, SessionPhase::Ready),
        can_sign_tx: matches!(phase, SessionPhase::Ready),
        requires_pairing_code: matches!(phase, SessionPhase::NeedsPairingCode),
        prompt_message,
    }
}

#[derive(Debug, Clone)]
pub struct SessionBootstrapOptions {
    pub thp_timeout: Duration,
    pub try_to_unlock: bool,
    pub passphrase: Option<String>,
    pub on_device: bool,
    pub derive_cardano: bool,
    pub retry_policy: SessionRetryPolicy,
}

impl Default for SessionBootstrapOptions {
    fn default() -> Self {
        Self {
            thp_timeout: Duration::from_secs(60),
            try_to_unlock: false,
            passphrase: None,
            on_device: false,
            derive_cardano: false,
            retry_policy: SessionRetryPolicy::default(),
        }
    }
}

pub async fn connect_and_bootstrap_session(
    device: DiscoveredDevice,
    profile: BleProfile,
    config: HostConfig,
    storage: Option<Arc<dyn ThpStorage>>,
    options: SessionBootstrapOptions,
) -> WalletResult<ThpWorkflow<BleBackend>> {
    let session = connect_trezor_device(device, profile).await?;
    let backend = backend_from_session(session, options.thp_timeout);

    let mut workflow = if let Some(storage) = storage {
        workflow_with_storage(backend, config, storage).await?
    } else {
        workflow(backend, config)
    };

    prepare_session_bootstrap(&mut workflow, &options).await?;
    Ok(workflow)
}

pub async fn prepare_session_bootstrap<B>(
    workflow: &mut ThpWorkflow<B>,
    options: &SessionBootstrapOptions,
) -> WalletResult<()>
where
    B: ThpBackend + Send,
{
    let mut session_ready = false;
    match advance_session_bootstrap(workflow, &mut session_ready, options).await? {
        SessionPhase::Ready => Ok(()),
        SessionPhase::NeedsPairingCode => Err(WalletError::Workflow(
            ThpWorkflowError::PairingInteractionRequired,
        )),
        _ => Err(WalletError::Workflow(ThpWorkflowError::InvalidPhase)),
    }
}

pub async fn establish_authenticated_phase<B>(
    workflow: &mut ThpWorkflow<B>,
    try_to_unlock: bool,
) -> WalletResult<()>
where
    B: ThpBackend + Send,
{
    match advance_to_paired(workflow, try_to_unlock).await? {
        SessionPhase::NeedsSession => Ok(()),
        SessionPhase::NeedsPairingCode => Err(WalletError::Workflow(
            ThpWorkflowError::PairingInteractionRequired,
        )),
        _ => Err(WalletError::Workflow(ThpWorkflowError::InvalidPhase)),
    }
}

pub async fn advance_to_paired<B>(
    workflow: &mut ThpWorkflow<B>,
    try_to_unlock: bool,
) -> WalletResult<SessionPhase>
where
    B: ThpBackend + Send,
{
    advance_to_paired_with_policy(workflow, try_to_unlock, &SessionRetryPolicy::default()).await
}

pub async fn advance_to_paired_with_policy<B>(
    workflow: &mut ThpWorkflow<B>,
    try_to_unlock: bool,
    retry_policy: &SessionRetryPolicy,
) -> WalletResult<SessionPhase>
where
    B: ThpBackend + Send,
{
    let retry_delay = retry_policy.retry_delay();
    loop {
        match session_phase(workflow.state(), false) {
            SessionPhase::NeedsChannel => {
                create_channel_with_retry(
                    workflow,
                    retry_policy.create_channel_attempts(),
                    retry_delay,
                )
                .await?;
            }
            SessionPhase::NeedsHandshake => {
                handshake_with_retry(
                    workflow,
                    try_to_unlock,
                    retry_policy.handshake_attempts(),
                    retry_delay,
                )
                .await?;
            }
            SessionPhase::NeedsConnectionConfirmation => {
                workflow.pairing(None).await.map_err(WalletError::from)?;
            }
            SessionPhase::NeedsPairingCode | SessionPhase::NeedsSession => {
                return Ok(session_phase(workflow.state(), false));
            }
            SessionPhase::Ready => unreachable!("session_ready is always false in paired mode"),
        }
    }
}

pub async fn advance_session_bootstrap<B>(
    workflow: &mut ThpWorkflow<B>,
    session_ready: &mut bool,
    options: &SessionBootstrapOptions,
) -> WalletResult<SessionPhase>
where
    B: ThpBackend + Send,
{
    let retry_delay = options.retry_policy.retry_delay();
    loop {
        match session_phase(workflow.state(), *session_ready) {
            SessionPhase::NeedsChannel => {
                create_channel_with_retry(
                    workflow,
                    options.retry_policy.create_channel_attempts(),
                    retry_delay,
                )
                .await?;
            }
            SessionPhase::NeedsHandshake => {
                handshake_with_retry(
                    workflow,
                    options.try_to_unlock,
                    options.retry_policy.handshake_attempts(),
                    retry_delay,
                )
                .await?;
            }
            SessionPhase::NeedsConnectionConfirmation => {
                workflow.pairing(None).await.map_err(WalletError::from)?;
            }
            SessionPhase::NeedsSession => {
                create_session_with_retry(
                    workflow,
                    options.passphrase.clone(),
                    options.on_device,
                    options.derive_cardano,
                    options.retry_policy.create_session_attempts(),
                    retry_delay,
                )
                .await?;
                *session_ready = true;
            }
            SessionPhase::NeedsPairingCode | SessionPhase::Ready => {
                return Ok(session_phase(workflow.state(), *session_ready));
            }
        }
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
                    BackendError::TransportTimeout,
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
    matches!(
        error,
        ThpWorkflowError::Backend(BackendError::TransportTimeout)
    )
}

fn is_retryable_handshake_error(error: &ThpWorkflowError) -> bool {
    matches!(
        error,
        ThpWorkflowError::Backend(BackendError::DeviceBusy | BackendError::TransportBusy)
    )
}

fn is_retryable_session_error(error: &ThpWorkflowError) -> bool {
    matches!(
        error,
        ThpWorkflowError::Backend(
            BackendError::DeviceBusy
                | BackendError::DeviceFirmwareBusy
                | BackendError::TransportBusy
                | BackendError::SessionConfirmationRequired
        )
    )
}

fn normalize_session_error(error: ThpWorkflowError) -> WalletError {
    match error {
        ThpWorkflowError::Backend(BackendError::DeviceFirmwareBusy) => {
            WalletError::Workflow(ThpWorkflowError::Backend(BackendError::Device(
                "device reported firmware busy (error code 99). Ensure the Trezor screen is unlocked and idle, then retry.".into(),
            )))
        }
        ThpWorkflowError::Backend(BackendError::DeviceBusy) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use trezor_connect::thp::PairingMethod;
    use trezor_connect::thp::state::HandshakeCache;

    #[test]
    fn session_phase_starts_with_channel_creation() {
        let state = ThpState::new();
        assert_eq!(session_phase(&state, false), SessionPhase::NeedsChannel);
    }

    #[test]
    fn session_phase_moves_to_handshake_after_channel() {
        let mut state = ThpState::new();
        state.set_handshake_cache(HandshakeCache {
            channel: 1,
            handshake_hash: vec![0xAA],
            pairing_methods: vec![PairingMethod::CodeEntry],
        });
        assert_eq!(session_phase(&state, false), SessionPhase::NeedsHandshake);
    }

    #[test]
    fn session_phase_distinguishes_pairing_code_vs_confirmation() {
        let mut state = ThpState::new();
        state.set_phase(Phase::Pairing);
        state.set_is_paired(false);
        assert_eq!(session_phase(&state, false), SessionPhase::NeedsPairingCode);

        state.set_is_paired(true);
        assert_eq!(
            session_phase(&state, false),
            SessionPhase::NeedsConnectionConfirmation
        );
    }

    #[test]
    fn session_phase_reports_ready_after_session_creation() {
        let mut state = ThpState::new();
        state.set_phase(Phase::Paired);
        assert_eq!(session_phase(&state, false), SessionPhase::NeedsSession);
        assert_eq!(session_phase(&state, true), SessionPhase::Ready);
    }

    #[test]
    fn session_phase_transition_sequence_progresses_to_ready() {
        let mut state = ThpState::new();
        let mut is_session_ready = false;

        assert_eq!(
            session_phase(&state, is_session_ready),
            SessionPhase::NeedsChannel
        );

        state.set_handshake_cache(HandshakeCache {
            channel: 7,
            handshake_hash: vec![0x01, 0x02],
            pairing_methods: vec![PairingMethod::CodeEntry],
        });
        assert_eq!(
            session_phase(&state, is_session_ready),
            SessionPhase::NeedsHandshake
        );

        state.set_phase(Phase::Pairing);
        state.set_is_paired(false);
        assert_eq!(
            session_phase(&state, is_session_ready),
            SessionPhase::NeedsPairingCode
        );

        state.set_is_paired(true);
        assert_eq!(
            session_phase(&state, is_session_ready),
            SessionPhase::NeedsConnectionConfirmation
        );

        state.set_phase(Phase::Paired);
        assert_eq!(
            session_phase(&state, is_session_ready),
            SessionPhase::NeedsSession
        );

        is_session_ready = true;
        assert_eq!(session_phase(&state, is_session_ready), SessionPhase::Ready);
    }

    #[test]
    fn session_state_flags_follow_phase() {
        let pairing = session_state(
            SessionPhase::NeedsPairingCode,
            Some("Enter code".to_string()),
        );
        assert!(pairing.can_pair_only);
        assert!(pairing.can_connect);
        assert!(!pairing.can_get_address);
        assert!(!pairing.can_sign_tx);
        assert!(pairing.requires_pairing_code);
        assert_eq!(pairing.prompt_message.as_deref(), Some("Enter code"));

        let ready = session_state(SessionPhase::Ready, None);
        assert!(!ready.can_pair_only);
        assert!(!ready.can_connect);
        assert!(ready.can_get_address);
        assert!(ready.can_sign_tx);
        assert!(!ready.requires_pairing_code);
        assert!(ready.prompt_message.is_none());
    }

    #[test]
    fn retry_policy_defaults_match_bootstrap_constants() {
        let policy = SessionRetryPolicy::default();
        assert_eq!(policy.create_channel_attempts(), CREATE_CHANNEL_ATTEMPTS);
        assert_eq!(policy.handshake_attempts(), HANDSHAKE_ATTEMPTS);
        assert_eq!(policy.create_session_attempts(), CREATE_SESSION_ATTEMPTS);
        assert_eq!(policy.retry_delay(), RETRY_DELAY);
    }

    #[test]
    fn retry_policy_enforces_minimum_values() {
        let policy = SessionRetryPolicy {
            create_channel_attempts: 0,
            handshake_attempts: 0,
            create_session_attempts: 0,
            retry_delay_ms: 0,
        };
        assert_eq!(policy.create_channel_attempts(), 1);
        assert_eq!(policy.handshake_attempts(), 1);
        assert_eq!(policy.create_session_attempts(), 1);
        assert_eq!(policy.retry_delay(), Duration::from_millis(1));
    }
}
