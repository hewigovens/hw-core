use trezor_connect::thp::ThpState;

use super::PairingPrompt;
use crate::errors::HWCoreError;

pub type SessionPhase = hw_wallet::ble::SessionPhase;

#[uniffi::remote(Enum)]
pub enum SessionPhase {
    NeedsChannel,
    NeedsHandshake,
    NeedsPairingCode,
    NeedsConnectionConfirmation,
    NeedsSession,
    Ready,
}

pub type SessionState = hw_wallet::ble::SessionState;

#[uniffi::remote(Record)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub can_pair_only: bool,
    pub can_connect: bool,
    pub can_get_address: bool,
    pub can_sign_tx: bool,
    pub requires_pairing_code: bool,
    pub prompt_message: Option<String>,
}

pub(crate) trait SessionStateExt: Sized {
    /// Also returns the pairing prompt when `phase` needs pairing input, for its event code.
    fn with_pairing_prompt(
        phase: SessionPhase,
        state: &ThpState,
    ) -> Result<(Self, Option<PairingPrompt>), HWCoreError>;
}

impl SessionStateExt for SessionState {
    fn with_pairing_prompt(
        phase: SessionPhase,
        state: &ThpState,
    ) -> Result<(Self, Option<PairingPrompt>), HWCoreError> {
        let prompt = if matches!(phase, SessionPhase::NeedsPairingCode) {
            Some(PairingPrompt::try_from(state)?)
        } else {
            None
        };
        let message = prompt.as_ref().map(|prompt| prompt.message.clone());
        Ok((Self::new(phase, message), prompt))
    }
}
