use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// Asks the backend to cancel the prompt the device is showing, keeping the channel open.
///
/// A request made while the device shows no prompt applies to the next prompt of the
/// running operation; call [`CancelHandle::clear`] before starting a new operation to drop it.
#[derive(Clone, Default)]
pub struct CancelHandle(Arc<CancelState>);

#[derive(Default)]
struct CancelState {
    requested: AtomicBool,
    notify: Notify,
}

impl CancelHandle {
    pub fn cancel(&self) {
        self.0.requested.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn clear(&self) {
        self.0.requested.store(false, Ordering::SeqCst);
    }

    pub fn is_requested(&self) -> bool {
        self.0.requested.load(Ordering::SeqCst)
    }

    /// Resolves once cancellation is requested, including a request made before the call.
    pub async fn requested(&self) {
        loop {
            let mut notified = pin!(self.0.notify.notified());
            notified.as_mut().enable();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn requested_resolves_for_earlier_and_later_cancel_until_cleared() {
        let handle = CancelHandle::default();
        handle.cancel();
        handle.requested().await;

        handle.clear();
        let pending = tokio::time::timeout(Duration::from_secs(1), handle.requested()).await;
        assert!(pending.is_err(), "cleared handle must not resolve");

        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move { handle.requested().await }
        });
        tokio::task::yield_now().await;
        handle.cancel();
        waiter.await.unwrap();
    }
}
