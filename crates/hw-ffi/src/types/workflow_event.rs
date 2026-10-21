use super::ButtonRequest;
use crate::errors::HWCoreError;

#[derive(uniffi::Enum, Clone, Debug)]
pub enum WorkflowEventKind {
    Progress,
    PairingPrompt,
    /// The device is showing a prompt; `button_request` says which.
    ButtonRequest,
    Ready,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct WorkflowEvent {
    pub kind: WorkflowEventKind,
    pub code: String,
    pub message: String,
    /// Set only for `ButtonRequest` events.
    pub button_request: Option<ButtonRequest>,
}

impl WorkflowEvent {
    pub(crate) fn new(kind: WorkflowEventKind, code: &str, message: &str) -> Self {
        Self {
            kind,
            code: code.to_string(),
            message: message.to_string(),
            button_request: None,
        }
    }
}

impl From<ButtonRequest> for WorkflowEvent {
    fn from(request: ButtonRequest) -> Self {
        Self {
            button_request: Some(request),
            ..Self::new(
                WorkflowEventKind::ButtonRequest,
                "BUTTON_REQUEST",
                "Review and confirm on the device",
            )
        }
    }
}

impl From<&HWCoreError> for WorkflowEvent {
    fn from(error: &HWCoreError) -> Self {
        Self::new(WorkflowEventKind::Error, error.code(), error.detail())
    }
}
