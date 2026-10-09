#[derive(uniffi::Enum, Clone, Debug, PartialEq, Eq)]
pub enum PairingProgressKind {
    AwaitingCode,
    AwaitingConnectionConfirmation,
    Completed,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingProgress {
    pub kind: PairingProgressKind,
    pub message: String,
}

impl PairingProgress {
    pub(crate) fn completed(message: &str) -> Self {
        Self {
            kind: PairingProgressKind::Completed,
            message: message.to_string(),
        }
    }
}
