use std::sync::Arc;

use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::thp::backend::ThpBackend;
use crate::thp::error::{Result, ThpWorkflowError};
use crate::thp::state::{Phase, ThpState};
use crate::thp::storage::{HostSnapshot, ThpStorage};
use crate::thp::types::HostConfig;

pub struct ThpWorkflow<B> {
    pub(super) backend: B,
    pub(super) config: HostConfig,
    pub(super) state: ThpState,
    pub(super) rng: StdRng,
    storage: Option<Arc<dyn ThpStorage>>,
    pub(super) channel_try_to_unlock: Option<bool>,
}

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub fn new(backend: B, config: HostConfig) -> Self {
        Self {
            backend,
            config,
            state: ThpState::new(),
            rng: StdRng::from_rng(&mut rand::rng()),
            storage: None,
            channel_try_to_unlock: None,
        }
    }

    pub async fn with_storage(
        backend: B,
        mut config: HostConfig,
        storage: Arc<dyn ThpStorage>,
    ) -> Result<Self> {
        storage
            .load()
            .await
            .map_err(ThpWorkflowError::Storage)?
            .restore(&mut config);
        Ok(Self {
            storage: Some(storage),
            ..Self::new(backend, config)
        })
    }

    pub fn state(&self) -> &ThpState {
        &self.state
    }

    pub fn host_config(&self) -> &HostConfig {
        &self.config
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn into_parts(self) -> (B, HostConfig, ThpState) {
        (self.backend, self.config, self.state)
    }

    pub async fn abort(&mut self) -> Result<()> {
        self.backend.abort().await?;
        self.state.reset();
        Ok(())
    }

    pub(super) fn require_phase(&self, phase: Phase) -> Result<()> {
        if self.state.phase() != phase {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        Ok(())
    }

    pub(super) async fn persist_host_state(&self) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage
                .persist(&HostSnapshot::from(&self.config))
                .await
                .map_err(ThpWorkflowError::Storage)?;
        }
        Ok(())
    }
}
