use super::handshake::{HandshakeCache, HandshakeCredentials};
use crate::thp::types::{KnownCredential, PairingMethod};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phase {
    #[default]
    Handshake,
    Pairing,
    Paired,
}

#[derive(Debug, Default)]
pub struct ThpState {
    phase: Phase,
    handshake_cache: Option<HandshakeCache>,
    handshake_credentials: Option<HandshakeCredentials>,
    pairing_method: Option<PairingMethod>,
    is_paired: bool,
}

impl ThpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }

    pub fn set_handshake_cache(&mut self, cache: HandshakeCache) {
        self.handshake_cache = Some(cache);
        self.phase = Phase::Handshake;
    }

    pub fn handshake_cache(&self) -> Option<&HandshakeCache> {
        self.handshake_cache.as_ref()
    }

    pub fn has_channel(&self) -> bool {
        self.handshake_cache.is_some()
    }

    pub fn set_handshake_credentials(&mut self, creds: HandshakeCredentials) {
        self.handshake_credentials = Some(creds);
        self.phase = Phase::Pairing;
    }

    pub fn handshake_credentials(&self) -> Option<&HandshakeCredentials> {
        self.handshake_credentials.as_ref()
    }

    pub fn update_handshake_credentials<F>(&mut self, update: F)
    where
        F: FnOnce(&mut HandshakeCredentials),
    {
        if let Some(creds) = self.handshake_credentials.as_mut() {
            update(creds);
        }
    }

    pub fn set_pairing_method(&mut self, method: PairingMethod) {
        self.pairing_method = Some(method);
    }

    pub fn pairing_method(&self) -> Option<PairingMethod> {
        self.pairing_method
    }

    /// Pairing methods both sides support, as negotiated by the handshake.
    pub fn pairing_methods(&self) -> &[PairingMethod] {
        self.handshake_credentials
            .as_ref()
            .map(|credentials| credentials.pairing_methods.as_slice())
            .unwrap_or_default()
    }

    /// The chosen pairing method, or else the device's preferred one from the handshake.
    pub fn selected_pairing_method(&self) -> Option<PairingMethod> {
        self.pairing_method.or_else(|| {
            self.handshake_credentials
                .as_ref()
                .and_then(HandshakeCredentials::preferred_pairing_method)
        })
    }

    /// Pairing can finish without user input because the selected method is SkipPairing.
    pub fn skip_pairing_pending(&self) -> bool {
        self.phase == Phase::Pairing
            && !self.is_paired
            && self.selected_pairing_method() == Some(PairingMethod::SkipPairing)
    }

    pub fn set_pairing_credentials(&mut self, credentials: Vec<KnownCredential>) {
        if let Some(creds) = self.handshake_credentials.as_mut() {
            creds.pairing_credentials = credentials;
        }
    }

    pub fn set_is_paired(&mut self, paired: bool) {
        self.is_paired = paired;
    }

    pub fn is_paired(&self) -> bool {
        self.is_paired
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_pairing_is_pending_only_for_unpaired_skip_pairing_selection() {
        for (methods, selected, is_paired, expected) in [
            (
                vec![PairingMethod::SkipPairing],
                Some(PairingMethod::SkipPairing),
                false,
                true,
            ),
            (vec![PairingMethod::SkipPairing], None, false, true),
            (vec![PairingMethod::SkipPairing], None, true, false),
            (
                vec![PairingMethod::CodeEntry],
                Some(PairingMethod::CodeEntry),
                false,
                false,
            ),
            (
                vec![PairingMethod::CodeEntry],
                Some(PairingMethod::SkipPairing),
                false,
                true,
            ),
        ] {
            let mut state = ThpState::new();
            state.set_handshake_credentials(HandshakeCredentials {
                pairing_methods: methods.clone(),
                ..HandshakeCredentials::default()
            });
            if let Some(method) = selected {
                state.set_pairing_method(method);
            }
            state.set_is_paired(is_paired);
            assert_eq!(
                state.skip_pairing_pending(),
                expected,
                "{methods:?} {selected:?} paired={is_paired}"
            );
        }
    }
}
