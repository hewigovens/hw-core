use trezor_connect::thp::{Phase, ThpState};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionPhase {
    NeedsChannel,
    NeedsHandshake,
    NeedsPairingCode,
    NeedsConnectionConfirmation,
    NeedsSession,
    Ready,
}

impl SessionPhase {
    pub fn from_state(state: &ThpState, session_ready: bool) -> Self {
        if session_ready {
            return Self::Ready;
        }
        match state.phase() {
            Phase::Handshake if state.has_channel() => Self::NeedsHandshake,
            Phase::Handshake => Self::NeedsChannel,
            Phase::Pairing if state.is_paired() => Self::NeedsConnectionConfirmation,
            Phase::Pairing => Self::NeedsPairingCode,
            Phase::Paired => Self::NeedsSession,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SessionState {
    pub phase: SessionPhase,
    pub can_pair_only: bool,
    pub can_connect: bool,
    pub can_get_address: bool,
    pub can_sign_tx: bool,
    pub requires_pairing_code: bool,
    pub prompt_message: Option<String>,
}

impl SessionState {
    pub fn new(phase: SessionPhase, prompt_message: Option<String>) -> Self {
        let ready = phase == SessionPhase::Ready;
        Self {
            phase,
            can_pair_only: !ready,
            can_connect: !ready,
            can_get_address: ready,
            can_sign_tx: ready,
            requires_pairing_code: phase == SessionPhase::NeedsPairingCode,
            prompt_message,
        }
    }
}
