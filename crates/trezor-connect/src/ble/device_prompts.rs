use crate::thp::types::{ButtonRequest, CancelHandle, DeviceEvent, DeviceEventSink};

/// Reports device prompts to the host app and carries its requests to cancel them.
#[derive(Default)]
pub(super) struct DevicePrompts {
    pub(super) sink: Option<DeviceEventSink>,
    pub(super) cancel: CancelHandle,
}

impl DevicePrompts {
    pub(super) fn announce(&self, payload: &[u8]) {
        let Some(sink) = &self.sink else {
            return;
        };
        let request = ButtonRequest::decode(payload).unwrap_or_default();
        sink(DeviceEvent::ButtonRequest(request));
    }
}
