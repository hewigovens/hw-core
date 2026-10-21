use trezor_connect::thp::{Phase, ThpState};

use super::PairingMethod;
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingPrompt {
    pub available_methods: Vec<PairingMethod>,
    pub selected_method: Option<PairingMethod>,
    pub requires_connection_confirmation: bool,
    pub message: String,
    /// Data to hand to the device over NFC, once NFC pairing is selected.
    pub nfc_data: Option<Vec<u8>>,
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum SessionHandshakeState {
    Ready,
    PairingRequired { prompt: PairingPrompt },
    ConnectionConfirmationRequired { prompt: PairingPrompt },
}

impl PairingPrompt {
    /// `PairingPrompt` event code, so apps that route on it open the right pairing screen.
    pub(crate) fn event_code(&self) -> &'static str {
        if self.requires_connection_confirmation {
            return "PAIRING_CONFIRMATION_REQUIRED";
        }
        match self.selected_method {
            Some(PairingMethod::QrCode) => "PAIRING_QR_CODE_REQUIRED",
            Some(PairingMethod::Nfc) => "PAIRING_NFC_REQUIRED",
            Some(PairingMethod::CodeEntry | PairingMethod::SkipPairing) | None => {
                "PAIRING_CODE_REQUIRED"
            }
        }
    }
}

impl TryFrom<&ThpState> for PairingPrompt {
    type Error = HWCoreError;

    fn try_from(state: &ThpState) -> Result<Self, Self::Error> {
        if state.phase() != Phase::Pairing {
            return Err(HWCoreError::Workflow(
                "pairing_start requires Pairing phase".to_string(),
            ));
        }

        let methods = state.pairing_methods().to_vec();
        let selected = state.pairing_method();
        let message = if state.is_paired() {
            "Connection confirmation is required for this already-paired device".to_string()
        } else if selected == Some(PairingMethod::QrCode) {
            "Scan the QR code shown on the Trezor to finish pairing".to_string()
        } else if selected == Some(PairingMethod::Nfc) {
            "Hold the phone to the Trezor to finish pairing over NFC".to_string()
        } else if methods.contains(&PairingMethod::CodeEntry) {
            "Enter the 6-digit code shown on the Trezor to finish pairing".to_string()
        } else {
            "Complete pairing on the device to finish connecting".to_string()
        };

        Ok(Self {
            available_methods: methods,
            selected_method: selected,
            requires_connection_confirmation: state.is_paired(),
            message,
            nfc_data: state
                .handshake_credentials()
                .and_then(|creds| creds.nfc_data.clone()),
        })
    }
}
