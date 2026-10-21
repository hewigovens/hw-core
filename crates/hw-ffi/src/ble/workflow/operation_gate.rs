use parking_lot::Mutex;
use trezor_connect::thp::CancelHandle;

/// Links the FFI's running operation to the backend's cancel handle.
///
/// Starting an operation drops any stale cancel and marks it active in one step, so a cancel
/// accepted after that always reaches the operation, and one made while idle is ignored.
pub(super) struct OperationGate {
    active: Mutex<bool>,
    cancel: CancelHandle,
}

impl OperationGate {
    pub(super) fn new(cancel: CancelHandle) -> Self {
        Self {
            active: Mutex::new(false),
            cancel,
        }
    }

    pub(super) fn begin(&self) -> OperationGuard<'_> {
        let mut active = self.active.lock();
        self.cancel.clear();
        *active = true;
        OperationGuard(&self.active)
    }

    /// Cancels the running operation's device prompt; a no-op while no operation runs.
    pub(super) fn request_cancel(&self) {
        let active = self.active.lock();
        if *active {
            self.cancel.cancel();
        }
    }
}

/// Marks the operation finished when dropped, including when the caller abandons the call.
pub(super) struct OperationGuard<'a>(&'a Mutex<bool>);

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        *self.0.lock() = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_reaches_running_operation_and_is_ignored_while_idle() {
        let cancel = CancelHandle::default();
        let gate = OperationGate::new(cancel.clone());

        gate.request_cancel();
        assert!(!cancel.is_requested(), "idle cancel must be ignored");

        let operation = gate.begin();
        gate.request_cancel();
        assert!(
            cancel.is_requested(),
            "cancel during the operation must stick"
        );
        drop(operation);

        let _next = gate.begin();
        assert!(
            !cancel.is_requested(),
            "a new operation starts without a stale cancel"
        );
    }
}
