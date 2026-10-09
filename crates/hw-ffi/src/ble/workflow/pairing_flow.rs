use trezor_connect::thp::{Phase, ThpBackend, ThpWorkflow, ThpWorkflowError};

use super::code_entry_controller::CodeEntryPairingController;
use crate::errors::HWCoreError;
use crate::types::{PairingProgress, PairingPrompt};

/// FFI pairing steps that validate the workflow phase before driving `ThpWorkflow::pairing`.
#[allow(async_fn_in_trait)]
pub(super) trait PairingFlow {
    async fn start_pairing(&mut self) -> Result<PairingPrompt, HWCoreError>;
    async fn confirm_paired_connection(&mut self) -> Result<PairingProgress, HWCoreError>;
    async fn submit_pairing_code(&mut self, code: String) -> Result<PairingProgress, HWCoreError>;
}

impl<B> PairingFlow for ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    async fn start_pairing(&mut self) -> Result<PairingPrompt, HWCoreError> {
        if self.state().phase() == Phase::Pairing
            && !self.state().is_paired()
            && let Err(err) = self.pairing(None).await
            && !matches!(err, ThpWorkflowError::PairingInteractionRequired)
        {
            return Err(err.into());
        }
        PairingPrompt::try_from(self.state())
    }

    async fn confirm_paired_connection(&mut self) -> Result<PairingProgress, HWCoreError> {
        if self.state().phase() != Phase::Pairing {
            return Err(HWCoreError::Workflow(
                "pairing_confirm_connection requires Pairing phase".to_string(),
            ));
        }
        if !self.state().is_paired() {
            return Err(HWCoreError::Validation(
                "device is not in paired-confirmation state; use pairing_submit_code".to_string(),
            ));
        }

        self.pairing(None).await?;
        Ok(PairingProgress::completed("Paired connection confirmed"))
    }

    async fn submit_pairing_code(&mut self, code: String) -> Result<PairingProgress, HWCoreError> {
        if self.state().phase() != Phase::Pairing {
            return Err(HWCoreError::Workflow(
                "pairing_submit_code requires Pairing phase".to_string(),
            ));
        }
        if self.state().is_paired() {
            return Err(HWCoreError::Validation(
                "device expects connection confirmation; use pairing_confirm_connection"
                    .to_string(),
            ));
        }

        let trimmed = code.trim();
        if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
            return Err(HWCoreError::Validation(
                "pairing code must be exactly 6 digits".to_string(),
            ));
        }

        match self
            .submit_code_entry_pairing_tag(trimmed.to_string())
            .await
        {
            Ok(()) => {}
            Err(ThpWorkflowError::PairingInteractionRequired) => {
                let controller = CodeEntryPairingController::new(trimmed.to_string());
                self.pairing(Some(&controller)).await?;
            }
            Err(err) => return Err(err.into()),
        }

        Ok(PairingProgress::completed("Pairing completed"))
    }
}
