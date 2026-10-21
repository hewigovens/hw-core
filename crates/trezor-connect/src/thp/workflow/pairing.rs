use std::ops::ControlFlow;

use tracing::debug;

use super::ThpWorkflow;
use crate::thp::backend::{BackendError, ThpBackend};
use crate::thp::error::{Result, ThpWorkflowError};
use crate::thp::state::{HandshakeCredentials, Phase};
use crate::thp::types::{
    KnownCredential, PairingController, PairingDecision, PairingMethod, PairingPrompt,
    PairingRequest, PairingTagRequest, PairingTagResponse, SelectMethodRequest,
    SelectMethodResponse,
};

/// What the pairing loop does after one prompt round.
pub(super) enum PairingStep {
    Accepted,
    Select(PairingMethod),
    Reprompt,
}

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub async fn pairing(&mut self, controller: Option<&dyn PairingController>) -> Result<()> {
        match self.state.phase() {
            Phase::Paired => return Ok(()),
            Phase::Pairing => {}
            Phase::Handshake => return Err(ThpWorkflowError::InvalidPhase),
        }

        let handshake = self
            .state
            .handshake_credentials()
            .cloned()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?;

        if self.state.is_paired()
            && handshake
                .preferred_pairing_method()
                .unwrap_or(PairingMethod::SkipPairing)
                != PairingMethod::SkipPairing
        {
            self.request_credential(&handshake).await?;
            self.backend.end_request().await?;
            self.state.set_phase(Phase::Paired);
            self.persist_host_state().await?;
            return Ok(());
        }

        self.backend
            .pairing_request(PairingRequest::new(
                &self.config.host_name,
                &self.config.app_name,
            ))
            .await?;

        let mut method = self
            .state
            .selected_pairing_method()
            .ok_or(ThpWorkflowError::NoCommonPairingMethod)?;
        let mut response = self.select_pairing_method(method).await?;
        loop {
            let step = match &response {
                SelectMethodResponse::End => {
                    // Firmware already exited pairing context; no end_request needed.
                    self.state.set_is_paired(true);
                    self.state.set_phase(Phase::Paired);
                    return Ok(());
                }
                SelectMethodResponse::CodeEntryCommitment { commitment } => {
                    self.code_entry_round(commitment.clone(), &handshake, method, controller)
                        .await?
                }
                SelectMethodResponse::PairingPreparationsFinished { nfc_data } => {
                    self.tag_round(nfc_data.clone(), &handshake, method, controller)
                        .await?
                }
            };
            match step {
                PairingStep::Accepted => break,
                PairingStep::Select(next) => {
                    method = next;
                    response = self.select_pairing_method(next).await?;
                }
                PairingStep::Reprompt => {}
            }
        }

        self.finalize_pairing_with_credential_request(&handshake)
            .await
    }

    /// Switches a started pairing to QR code or NFC, so the device shows its code or waits for NFC.
    ///
    /// Call after the pairing request was sent (e.g. when code entry waits for the user). Returns
    /// the data the app hands to the device over NFC, for `PairingMethod::Nfc`.
    pub async fn select_tag_pairing_method(
        &mut self,
        method: PairingMethod,
    ) -> Result<Option<Vec<u8>>> {
        let handshake = self.unpaired_handshake()?;
        if !matches!(method, PairingMethod::QrCode | PairingMethod::Nfc) {
            return Err(BackendError::UnsupportedPairingMethod.into());
        }
        if !handshake.pairing_methods.contains(&method) {
            return Err(ThpWorkflowError::NoCommonPairingMethod);
        }
        match self.select_pairing_method(method).await? {
            SelectMethodResponse::PairingPreparationsFinished { nfc_data } => {
                self.state.update_handshake_credentials(|creds| {
                    creds.nfc_data = nfc_data.clone();
                });
                Ok(nfc_data)
            }
            SelectMethodResponse::End => {
                self.state.set_is_paired(true);
                self.state.set_phase(Phase::Paired);
                Ok(None)
            }
            SelectMethodResponse::CodeEntryCommitment { .. } => Err(BackendError::Transport(
                "unexpected code-entry commitment after selecting a tag method".into(),
            )
            .into()),
        }
    }

    /// Completes QR code or NFC pairing with the tag the app read from the device (hex).
    pub async fn submit_pairing_tag(&mut self, tag: String) -> Result<()> {
        let handshake = self.unpaired_handshake()?;
        let request = self
            .state
            .pairing_method()
            .and_then(|method| {
                PairingTagRequest::for_tag_method(method, handshake.handshake_hash.clone(), tag)
            })
            .ok_or(ThpWorkflowError::PairingInteractionRequired)?;
        match self.backend.send_pairing_tag(request).await? {
            PairingTagResponse::Accepted { .. } => {}
            PairingTagResponse::Retry(reason) => {
                return Err(BackendError::Device(reason).into());
            }
        }
        self.finalize_pairing_with_credential_request(&handshake)
            .await
    }

    /// Handshake credentials of a pairing that still needs a tag.
    pub(super) fn unpaired_handshake(&self) -> Result<HandshakeCredentials> {
        self.require_phase(Phase::Pairing)?;
        if self.state.is_paired() {
            return Err(ThpWorkflowError::AlreadyPaired);
        }
        self.state
            .handshake_credentials()
            .cloned()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)
    }

    /// Prompts for a tag of `method`; any other decision asks the loop to select that method.
    pub(super) async fn prompt_for_tag(
        &self,
        controller: Option<&dyn PairingController>,
        prompt: PairingPrompt,
    ) -> Result<ControlFlow<PairingStep, String>> {
        let Some(controller) = controller else {
            return Err(ThpWorkflowError::PairingInteractionRequired);
        };
        let method = prompt.selected_method;
        let decision = controller
            .on_prompt(prompt)
            .await
            .map_err(ThpWorkflowError::PairingController)?;
        Ok(match decision {
            PairingDecision::SubmitTag {
                method: chosen,
                tag,
            } if chosen == method => ControlFlow::Continue(tag),
            PairingDecision::SubmitTag { method: next, .. }
            | PairingDecision::SwitchMethod(next) => ControlFlow::Break(PairingStep::Select(next)),
        })
    }

    pub(super) async fn finalize_pairing_with_credential_request(
        &mut self,
        handshake: &HandshakeCredentials,
    ) -> Result<()> {
        self.request_credential(handshake).await?;
        self.state.set_is_paired(true);
        self.state.set_phase(Phase::Paired);
        self.backend.end_request().await?;
        self.persist_host_state().await?;
        Ok(())
    }

    async fn select_pairing_method(
        &mut self,
        method: PairingMethod,
    ) -> Result<SelectMethodResponse> {
        self.state.set_pairing_method(method);
        Ok(self
            .backend
            .select_pairing_method(SelectMethodRequest { method })
            .await?)
    }

    async fn tag_round(
        &mut self,
        nfc_data: Option<Vec<u8>>,
        handshake: &HandshakeCredentials,
        method: PairingMethod,
        controller: Option<&dyn PairingController>,
    ) -> Result<PairingStep> {
        // Store NFC data before prompting: without a controller the prompt returns
        // PairingInteractionRequired, and the app reads the data from the workflow state.
        if let Some(data) = &nfc_data {
            self.state.update_handshake_credentials(|creds| {
                creds.nfc_data = Some(data.clone());
            });
        }
        let prompt = PairingPrompt {
            available_methods: handshake.pairing_methods.clone(),
            selected_method: method,
            nfc_data: nfc_data.or(handshake.nfc_data.clone()),
        };
        let tag = match self.prompt_for_tag(controller, prompt).await? {
            ControlFlow::Continue(tag) => tag,
            ControlFlow::Break(step) => return Ok(step),
        };

        let Some(request) =
            PairingTagRequest::for_tag_method(method, handshake.handshake_hash.clone(), tag)
        else {
            return Ok(PairingStep::Reprompt);
        };

        match self.backend.send_pairing_tag(request).await? {
            PairingTagResponse::Accepted { .. } => Ok(PairingStep::Accepted),
            PairingTagResponse::Retry(reason) => {
                debug!("pairing tag retry requested: {reason}");
                Ok(PairingStep::Reprompt)
            }
        }
    }

    async fn request_credential(&mut self, handshake: &HandshakeCredentials) -> Result<()> {
        let response = self
            .backend
            .credential_request(handshake.credential_request())
            .await?;
        let credential = KnownCredential::from(response);
        self.config.remember_credential(credential.clone());
        self.state.set_pairing_credentials(vec![credential]);
        Ok(())
    }
}
