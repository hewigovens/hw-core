use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::debug;
use trezor_connect::thp::{BackendError, ThpBackend, ThpWorkflow, ThpWorkflowError};

use super::retry_policy::SessionRetryPolicy;
use super::session_state::SessionPhase;
use super::workflow_error::WorkflowErrorExt;
use crate::error::WalletResult;

const CREATE_CHANNEL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BootstrapTarget {
    Paired,
    Session,
}

#[allow(async_fn_in_trait)]
pub trait SessionBootstrap {
    /// Drives the workflow until it reaches `target` or needs pairing-code input.
    async fn advance_session_bootstrap(
        &mut self,
        session_ready: bool,
        target: BootstrapTarget,
        options: &SessionBootstrapOptions,
    ) -> WalletResult<SessionPhase>;
}

impl<B> SessionBootstrap for ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    async fn advance_session_bootstrap(
        &mut self,
        session_ready: bool,
        target: BootstrapTarget,
        options: &SessionBootstrapOptions,
    ) -> WalletResult<SessionPhase> {
        Bootstrapper {
            workflow: self,
            options,
        }
        .advance(session_ready, target)
        .await
    }
}

struct Bootstrapper<'a, B> {
    workflow: &'a mut ThpWorkflow<B>,
    options: &'a SessionBootstrapOptions,
}

impl<B> Bootstrapper<'_, B>
where
    B: ThpBackend + Send,
{
    async fn advance(
        &mut self,
        mut session_ready: bool,
        target: BootstrapTarget,
    ) -> WalletResult<SessionPhase> {
        loop {
            if self.workflow.state().skip_pairing_pending() {
                self.workflow.pairing(None).await?;
                continue;
            }

            match SessionPhase::from_state(self.workflow.state(), session_ready) {
                SessionPhase::NeedsChannel => self.create_channel().await?,
                SessionPhase::NeedsHandshake => self.handshake().await?,
                SessionPhase::NeedsConnectionConfirmation => self.workflow.pairing(None).await?,
                SessionPhase::NeedsSession if target == BootstrapTarget::Session => {
                    self.create_session().await?;
                    session_ready = true;
                }
                phase @ (SessionPhase::NeedsSession
                | SessionPhase::NeedsPairingCode
                | SessionPhase::Ready) => return Ok(phase),
            }
        }
    }

    fn policy(&self) -> &SessionRetryPolicy {
        &self.options.retry_policy
    }

    async fn create_channel(&mut self) -> WalletResult<()> {
        let attempts = self.policy().create_channel_attempts();
        let retry_delay = self.policy().retry_delay();
        let mut attempt = 1;
        loop {
            let result = timeout(
                CREATE_CHANNEL_ATTEMPT_TIMEOUT,
                self.workflow.create_channel(),
            )
            .await
            .unwrap_or(Err(ThpWorkflowError::Backend(
                BackendError::TransportTimeout,
            )));
            match result {
                Ok(()) => return Ok(()),
                Err(err) if err.is_transport_timeout() && attempt < attempts => {
                    debug!(
                        "create-channel timed out on attempt {}; retrying after {:?}",
                        attempt, retry_delay
                    );
                    sleep(retry_delay).await;
                    attempt += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn handshake(&mut self) -> WalletResult<()> {
        let attempts = self.policy().handshake_attempts();
        let retry_delay = self.policy().retry_delay();
        let mut attempt = 1;
        loop {
            match self.workflow.handshake(self.options.try_to_unlock).await {
                Ok(()) => return Ok(()),
                Err(err) if err.is_retryable_handshake() && attempt < attempts => {
                    debug!(
                        "handshake failed with transient device state on attempt {}; retrying after {:?}",
                        attempt, retry_delay
                    );
                    sleep(retry_delay).await;
                    self.create_channel().await?;
                    attempt += 1;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    async fn create_session(&mut self) -> WalletResult<()> {
        let attempts = self.policy().create_session_attempts();
        let retry_delay = self.policy().retry_delay();
        let mut attempt = 1;
        loop {
            match self
                .workflow
                .create_session(
                    self.options.passphrase.clone(),
                    self.options.on_device,
                    self.options.derive_cardano,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(err) if err.is_retryable_session() && attempt < attempts => {
                    debug!(
                        "create-session hit transient device state on attempt {}; retrying after {:?}",
                        attempt, retry_delay
                    );
                    sleep(retry_delay).await;
                    attempt += 1;
                }
                Err(err) => return Err(err.into_session_error()),
            }
        }
    }
}
