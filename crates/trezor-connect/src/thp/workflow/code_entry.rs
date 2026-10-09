use std::ops::ControlFlow;

use rand::RngExt;
use tracing::debug;

use super::ThpWorkflow;
use super::pairing::PairingStep;
use crate::thp::backend::{BackendError, ThpBackend};
use crate::thp::error::{Result, ThpWorkflowError};
use crate::thp::state::{HandshakeCredentials, Phase};
use crate::thp::types::{
    CodeEntryChallengeRequest, PairingController, PairingMethod, PairingPrompt, PairingTagResponse,
};

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub async fn submit_code_entry_pairing_tag(&mut self, code: String) -> Result<()> {
        self.require_phase(Phase::Pairing)?;
        if self.state.is_paired() {
            return Err(ThpWorkflowError::AlreadyPaired);
        }

        let handshake = self
            .state
            .handshake_credentials()
            .cloned()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?;

        if self.state.pairing_method() != Some(PairingMethod::CodeEntry)
            || !handshake.has_code_entry_inputs()
        {
            return Err(ThpWorkflowError::PairingInteractionRequired);
        }

        match self
            .backend
            .send_pairing_tag(handshake.code_entry_tag(code))
            .await?
        {
            PairingTagResponse::Accepted { .. } => {}
            PairingTagResponse::Retry(reason) => {
                return Err(ThpWorkflowError::Backend(BackendError::Device(reason)));
            }
        }

        self.finalize_pairing_with_credential_request(&handshake)
            .await
    }

    /// Runs one CPace exchange for `commitment`; rejected challenges and tags request a fresh commitment.
    pub(super) async fn code_entry_round(
        &mut self,
        commitment: Vec<u8>,
        handshake: &HandshakeCredentials,
        method: PairingMethod,
        controller: Option<&dyn PairingController>,
    ) -> Result<PairingStep> {
        debug!(
            "code-entry commitment received: commitment_len={}",
            commitment.len(),
        );
        self.state.update_handshake_credentials(|creds| {
            creds.handshake_commitment = Some(commitment);
        });

        let mut challenge = vec![0u8; 32];
        self.rng.fill(challenge.as_mut_slice());
        debug!(
            "code-entry: sending ThpCodeEntryChallenge, challenge_len={}",
            challenge.len()
        );
        self.state.update_handshake_credentials(|creds| {
            creds.code_entry_challenge = Some(challenge.clone());
        });
        let cpace_response = match self
            .backend
            .code_entry_challenge(CodeEntryChallengeRequest { challenge })
            .await
        {
            Ok(response) => response,
            Err(BackendError::Device(reason)) => {
                debug!(
                    "code-entry challenge rejected by device: {reason}; requesting fresh commitment"
                );
                return Ok(PairingStep::Select(method));
            }
            Err(err) => return Err(err.into()),
        };
        debug!(
            "code-entry: received ThpCodeEntryCpaceTrezor, public_key_len={}",
            cpace_response.trezor_cpace_public_key.len()
        );
        self.state.update_handshake_credentials(|creds| {
            creds.trezor_cpace_public_key = Some(cpace_response.trezor_cpace_public_key);
        });

        let prompt = PairingPrompt {
            available_methods: handshake.pairing_methods.clone(),
            selected_method: method,
            nfc_data: None,
        };
        let code = match self.prompt_for_tag(controller, prompt).await? {
            ControlFlow::Continue(code) => code,
            ControlFlow::Break(step) => return Ok(step),
        };

        let request = self
            .state
            .handshake_credentials()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?
            .code_entry_tag(code);
        match self.backend.send_pairing_tag(request).await? {
            PairingTagResponse::Accepted { .. } => Ok(PairingStep::Accepted),
            PairingTagResponse::Retry(reason) => {
                debug!("code entry retry requested: {reason}; requesting fresh commitment");
                Ok(PairingStep::Select(method))
            }
        }
    }
}
