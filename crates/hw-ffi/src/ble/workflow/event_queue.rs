use std::collections::VecDeque;
use std::pin::pin;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio::time::timeout;

use crate::types::WorkflowEvent;

/// Workflow events awaiting `next_event`; pushed from API calls and the backend's receive loop.
#[derive(Default)]
pub(super) struct EventQueue {
    events: Mutex<VecDeque<WorkflowEvent>>,
    notify: Notify,
}

impl EventQueue {
    pub(super) fn push(&self, event: WorkflowEvent) {
        self.events.lock().push_back(event);
        self.notify.notify_waiters();
    }

    pub(super) async fn next(&self, timeout_ms: Option<u64>) -> Option<WorkflowEvent> {
        loop {
            let mut notified = pin!(self.notify.notified());
            notified.as_mut().enable();
            if let Some(event) = self.events.lock().pop_front() {
                return Some(event);
            }
            match timeout_ms {
                Some(timeout_ms) => {
                    timeout(Duration::from_millis(timeout_ms), notified)
                        .await
                        .ok()?;
                }
                None => notified.await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use trezor_connect::thp::{self, DeviceEvent};

    use super::*;
    use crate::types::{ButtonRequest, ButtonRequestCode, WorkflowEventKind};

    #[tokio::test]
    async fn device_prompt_from_backend_wakes_pending_next_event() {
        let queue = std::sync::Arc::new(EventQueue::default());
        let waiter = tokio::spawn({
            let queue = queue.clone();
            async move { queue.next(Some(60_000)).await }
        });
        tokio::task::yield_now().await;

        let event = DeviceEvent::ButtonRequest(thp::ButtonRequest {
            code: None,
            pages: Some(3),
            name: Some("confirm_output".into()),
        });
        queue.push(ButtonRequest::from_device_event(event).into());

        let event = waiter.await.unwrap().expect("queued event");
        assert!(matches!(event.kind, WorkflowEventKind::ButtonRequest));
        assert_eq!(
            event.button_request,
            Some(ButtonRequest {
                code: ButtonRequestCode::Unknown,
                pages: Some(3),
                name: Some("confirm_output".into()),
            })
        );
        assert!(queue.next(Some(10)).await.is_none());
    }
}
