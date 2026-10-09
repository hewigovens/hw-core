use crate::errors::HWCoreError;

#[derive(uniffi::Enum, Clone, Debug)]
pub enum WorkflowEventKind {
    Progress,
    PairingPrompt,
    ButtonRequest,
    Ready,
    Error,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct WorkflowEvent {
    pub kind: WorkflowEventKind,
    pub code: String,
    pub message: String,
}

impl WorkflowEvent {
    pub(crate) fn new(kind: WorkflowEventKind, code: &str, message: &str) -> Self {
        Self {
            kind,
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl From<&HWCoreError> for WorkflowEvent {
    fn from(error: &HWCoreError) -> Self {
        Self::new(WorkflowEventKind::Error, error.code(), error.detail())
    }
}
