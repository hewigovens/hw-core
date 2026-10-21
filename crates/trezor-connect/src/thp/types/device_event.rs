use std::sync::Arc;

/// Screen the device shows while it waits for the user (firmware `ButtonRequestType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonRequestCode {
    Other,
    FeeOverThreshold,
    ConfirmOutput,
    ResetDevice,
    ConfirmWord,
    WipeDevice,
    ProtectCall,
    SignTx,
    FirmwareCheck,
    Address,
    PublicKey,
    MnemonicWordCount,
    MnemonicInput,
    UnknownDerivationPath,
    RecoveryHomepage,
    Success,
    Warning,
    PassphraseEntry,
    PinEntry,
}

/// A prompt the device is showing; the host acknowledges it and waits for the user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ButtonRequest {
    /// `None` when the firmware sends no code or one this crate does not know.
    pub code: Option<ButtonRequestCode>,
    pub pages: Option<u32>,
    /// Firmware screen name, e.g. `confirm_output`.
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceEvent {
    ButtonRequest(ButtonRequest),
}

/// Receives device events as they arrive, from inside the backend's receive loop; must not block.
pub type DeviceEventSink = Arc<dyn Fn(DeviceEvent) + Send + Sync>;
