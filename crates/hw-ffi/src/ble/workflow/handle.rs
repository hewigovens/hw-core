use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::time::timeout;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::ThpWorkflow;

use crate::errors::HWCoreError;
use crate::types::{SessionPhase, SessionState, WorkflowEvent, WorkflowEventKind};

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    pub(super) workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
    pub(super) session_ready: AsyncMutex<bool>,
    events: AsyncMutex<VecDeque<WorkflowEvent>>,
    notify: Notify,
}

impl BleWorkflowHandle {
    pub(crate) fn new(workflow: ThpWorkflow<BleBackend>) -> Self {
        Self {
            workflow: AsyncMutex::new(workflow),
            session_ready: AsyncMutex::new(false),
            events: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
        }
    }

    /// Wraps a workflow that already has a session and announces it as ready.
    pub(crate) async fn ready(workflow: ThpWorkflow<BleBackend>) -> Self {
        let handle = Self::new(workflow);
        *handle.session_ready.lock().await = true;
        handle.push_session_ready().await;
        handle
    }

    /// Runs `op` under the workflow lock and reports its failure as an error event.
    pub(super) async fn with_workflow<T>(
        &self,
        op: impl AsyncFnOnce(&mut ThpWorkflow<BleBackend>) -> Result<T, HWCoreError>,
    ) -> Result<T, HWCoreError> {
        let result = {
            let mut workflow = self.workflow.lock().await;
            op(&mut workflow).await
        };
        if let Err(err) = &result {
            self.push_event(err.into()).await;
        }
        result
    }

    pub(super) async fn next_queued_event(&self, timeout_ms: Option<u64>) -> Option<WorkflowEvent> {
        loop {
            if let Some(event) = self.events.lock().await.pop_front() {
                return Some(event);
            }

            let notified = self.notify.notified();
            if let Some(timeout_ms) = timeout_ms {
                if timeout(Duration::from_millis(timeout_ms), notified)
                    .await
                    .is_err()
                {
                    return None;
                }
            } else {
                notified.await;
            }
        }
    }

    async fn push_event(&self, event: WorkflowEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
        self.notify.notify_waiters();
    }

    pub(super) async fn push(&self, kind: WorkflowEventKind, code: &str, message: &str) {
        self.push_event(WorkflowEvent::new(kind, code, message))
            .await;
    }

    pub(super) async fn progress(&self, code: &str, message: &str) {
        self.push(WorkflowEventKind::Progress, code, message).await;
    }

    pub(super) async fn confirmation_possible(&self, message: &str) {
        self.push(
            WorkflowEventKind::ButtonRequest,
            "DEVICE_CONFIRMATION_POSSIBLE",
            message,
        )
        .await;
    }

    async fn push_session_ready(&self) {
        self.push(
            WorkflowEventKind::Ready,
            "SESSION_READY",
            "BLE workflow is authenticated and session-ready",
        )
        .await;
    }

    pub(super) async fn push_session_state_event(&self, state: &SessionState) {
        match (&state.phase, &state.prompt_message) {
            (SessionPhase::Ready, _) => self.push_session_ready().await,
            (SessionPhase::NeedsPairingCode, Some(message)) => {
                self.push(
                    WorkflowEventKind::PairingPrompt,
                    "PAIRING_CODE_REQUIRED",
                    message,
                )
                .await;
            }
            _ => {}
        }
    }
}
