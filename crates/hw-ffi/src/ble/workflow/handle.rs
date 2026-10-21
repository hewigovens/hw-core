use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{CancelHandle, ThpWorkflow};

use super::event_queue::EventQueue;
use crate::errors::HWCoreError;
use crate::types::{ButtonRequest, SessionPhase, SessionState, WorkflowEvent, WorkflowEventKind};

#[derive(uniffi::Object)]
pub struct BleWorkflowHandle {
    pub(super) workflow: AsyncMutex<ThpWorkflow<BleBackend>>,
    pub(super) session_ready: AsyncMutex<bool>,
    pub(super) cancel: CancelHandle,
    events: Arc<EventQueue>,
}

impl BleWorkflowHandle {
    pub(crate) fn new(mut workflow: ThpWorkflow<BleBackend>) -> Self {
        let events = Arc::new(EventQueue::default());
        let sink_events = events.clone();
        workflow
            .backend_mut()
            .set_event_sink(Some(Arc::new(move |event| {
                sink_events.push(ButtonRequest::from_device_event(event).into());
            })));
        Self {
            cancel: workflow.backend().cancel_handle(),
            workflow: AsyncMutex::new(workflow),
            session_ready: AsyncMutex::new(false),
            events,
        }
    }

    /// Wraps a workflow that already has a session and announces it as ready.
    pub(crate) async fn ready(workflow: ThpWorkflow<BleBackend>) -> Self {
        let handle = Self::new(workflow);
        *handle.session_ready.lock().await = true;
        handle.push_session_ready();
        handle
    }

    /// Runs `op` under the workflow lock and reports its failure as an error event.
    pub(super) async fn with_workflow<T>(
        &self,
        op: impl AsyncFnOnce(&mut ThpWorkflow<BleBackend>) -> Result<T, HWCoreError>,
    ) -> Result<T, HWCoreError> {
        let result = {
            let mut workflow = self.workflow.lock().await;
            // A cancel requested while no operation ran must not hit this one.
            self.cancel.clear();
            let result = op(&mut workflow).await;
            if matches!(
                result,
                Err(HWCoreError::Timeout(_) | HWCoreError::Disconnected(_))
            ) {
                // The backend retired its channel; the next connect_ready must redo the handshake.
                workflow.forget_channel();
                *self.session_ready.lock().await = false;
            }
            result
        };
        if let Err(err) = &result {
            self.events.push(err.into());
        }
        result
    }

    pub(super) async fn next_queued_event(&self, timeout_ms: Option<u64>) -> Option<WorkflowEvent> {
        self.events.next(timeout_ms).await
    }

    pub(super) fn push(&self, kind: WorkflowEventKind, code: &str, message: &str) {
        self.events.push(WorkflowEvent::new(kind, code, message));
    }

    pub(super) fn progress(&self, code: &str, message: &str) {
        self.push(WorkflowEventKind::Progress, code, message);
    }

    fn push_session_ready(&self) {
        self.push(
            WorkflowEventKind::Ready,
            "SESSION_READY",
            "BLE workflow is authenticated and session-ready",
        );
    }

    pub(super) fn push_session_state_event(&self, state: &SessionState) {
        match (&state.phase, &state.prompt_message) {
            (SessionPhase::Ready, _) => self.push_session_ready(),
            (SessionPhase::NeedsPairingCode, Some(message)) => {
                self.push(
                    WorkflowEventKind::PairingPrompt,
                    "PAIRING_CODE_REQUIRED",
                    message,
                );
            }
            _ => {}
        }
    }
}
