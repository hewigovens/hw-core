use trezor_connect::thp::{Phase, ThpState};

use super::PairingMethod;
use crate::errors::HWCoreError;

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingPrompt {
    pub available_methods: Vec<PairingMethod>,
    pub selected_method: Option<PairingMethod>,
    pub requires_connection_confirmation: bool,
    pub message: String,
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum SessionHandshakeState {
    Ready,
    PairingRequired { prompt: PairingPrompt },
    ConnectionConfirmationRequired { prompt: PairingPrompt },
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
        let message = if state.is_paired() {
            "Connection confirmation is required for this already-paired device".to_string()
        } else if methods.contains(&PairingMethod::CodeEntry) {
            "Enter the 6-digit code shown on the Trezor to finish pairing".to_string()
        } else {
            "Complete pairing on the device to finish connecting".to_string()
        };

        Ok(Self {
            available_methods: methods,
            selected_method: state.pairing_method(),
            requires_connection_confirmation: state.is_paired(),
            message,
        })
    }
}
