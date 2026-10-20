use trezor_connect::thp::{self, DeviceEvent};

/// Screen the device shows while it waits for the user.
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
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
    /// The firmware sent no code, or one this version does not know.
    Unknown,
}

/// A prompt the device is showing right now; the user must act on the device.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct ButtonRequest {
    pub code: ButtonRequestCode,
    pub pages: Option<u32>,
    /// Firmware screen name, e.g. `confirm_output`.
    pub name: Option<String>,
}

impl From<thp::ButtonRequestCode> for ButtonRequestCode {
    fn from(code: thp::ButtonRequestCode) -> Self {
        use thp::ButtonRequestCode as Code;
        match code {
            Code::Other => Self::Other,
            Code::FeeOverThreshold => Self::FeeOverThreshold,
            Code::ConfirmOutput => Self::ConfirmOutput,
            Code::ResetDevice => Self::ResetDevice,
            Code::ConfirmWord => Self::ConfirmWord,
            Code::WipeDevice => Self::WipeDevice,
            Code::ProtectCall => Self::ProtectCall,
            Code::SignTx => Self::SignTx,
            Code::FirmwareCheck => Self::FirmwareCheck,
            Code::Address => Self::Address,
            Code::PublicKey => Self::PublicKey,
            Code::MnemonicWordCount => Self::MnemonicWordCount,
            Code::MnemonicInput => Self::MnemonicInput,
            Code::UnknownDerivationPath => Self::UnknownDerivationPath,
            Code::RecoveryHomepage => Self::RecoveryHomepage,
            Code::Success => Self::Success,
            Code::Warning => Self::Warning,
            Code::PassphraseEntry => Self::PassphraseEntry,
            Code::PinEntry => Self::PinEntry,
        }
    }
}

impl From<thp::ButtonRequest> for ButtonRequest {
    fn from(request: thp::ButtonRequest) -> Self {
        Self {
            code: request
                .code
                .map_or(ButtonRequestCode::Unknown, ButtonRequestCode::from),
            pages: request.pages,
            name: request.name,
        }
    }
}

impl ButtonRequest {
    pub(crate) fn from_device_event(event: DeviceEvent) -> Self {
        match event {
            DeviceEvent::ButtonRequest(request) => request.into(),
        }
    }
}
