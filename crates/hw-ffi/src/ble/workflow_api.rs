use super::*;
use hw_wallet::ble::{BootstrapTarget, advance_session_bootstrap};
use std::time::Duration;
use tokio::time::timeout;
use trezor_connect::thp::ThpWorkflowError;

#[uniffi::export(async_runtime = "tokio")]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn session_state(&self) -> Result<SessionState, HWCoreError> {
        let ready = *self.session_ready.lock().await;
        let workflow = self.workflow.lock().await;
        session_state_for(&workflow, session_phase(workflow.state(), ready))
    }

    #[uniffi::method]
    pub async fn pair_only(&self, try_to_unlock: bool) -> Result<SessionState, HWCoreError> {
        self.pair_only_with_policy(try_to_unlock, None).await
    }

    #[uniffi::method]
    pub async fn pair_only_with_policy(
        &self,
        try_to_unlock: bool,
        retry_policy: Option<SessionRetryPolicy>,
    ) -> Result<SessionState, HWCoreError> {
        self.progress("PAIR_ONLY_START", "Advancing workflow to paired state")
            .await;
        let options = bootstrap_options(try_to_unlock, retry_policy);
        let result = self
            .with_workflow(async |workflow| {
                let phase =
                    advance_session_bootstrap(workflow, false, BootstrapTarget::Paired, &options)
                        .await?;
                session_state_for(workflow, phase)
            })
            .await;
        *self.session_ready.lock().await = false;
        let state = result?;
        self.push_session_state_event(&state).await;
        Ok(state)
    }

    #[uniffi::method]
    pub async fn connect_ready(&self, try_to_unlock: bool) -> Result<SessionState, HWCoreError> {
        self.connect_ready_with_policy(try_to_unlock, None).await
    }

    #[uniffi::method]
    pub async fn connect_ready_with_policy(
        &self,
        try_to_unlock: bool,
        retry_policy: Option<SessionRetryPolicy>,
    ) -> Result<SessionState, HWCoreError> {
        self.progress(
            "CONNECT_READY_START",
            "Advancing workflow to session-ready state",
        )
        .await;
        let ready = *self.session_ready.lock().await;
        let options = bootstrap_options(try_to_unlock, retry_policy);
        let state = self
            .with_workflow(async |workflow| {
                let phase =
                    advance_session_bootstrap(workflow, ready, BootstrapTarget::Session, &options)
                        .await?;
                session_state_for(workflow, phase)
            })
            .await?;
        *self.session_ready.lock().await = matches!(state.phase, WalletSessionPhase::Ready);
        self.push_session_state_event(&state).await;
        Ok(state)
    }

    #[uniffi::method]
    pub async fn prepare_channel_and_handshake(
        &self,
        try_to_unlock: bool,
    ) -> Result<SessionHandshakeState, HWCoreError> {
        self.create_channel().await?;
        self.handshake(try_to_unlock).await?;

        let phase = self.workflow.lock().await.state().phase();
        match phase {
            Phase::Paired => Ok(SessionHandshakeState::Ready),
            Phase::Pairing => {
                let prompt = self.pairing_start().await?;
                if prompt.requires_connection_confirmation {
                    Ok(SessionHandshakeState::ConnectionConfirmationRequired { prompt })
                } else {
                    Ok(SessionHandshakeState::PairingRequired { prompt })
                }
            }
            Phase::Handshake => Err(HWCoreError::Workflow(
                "unexpected handshake phase".to_string(),
            )),
        }
    }

    #[uniffi::method]
    pub async fn pairing_start(&self) -> Result<PairingPrompt, HWCoreError> {
        let prompt = self
            .with_workflow(async |workflow| {
                if workflow.state().phase() == Phase::Pairing
                    && !workflow.state().is_paired()
                    && let Err(err) = workflow.pairing(None).await
                    && !matches!(err, ThpWorkflowError::PairingInteractionRequired)
                {
                    return Err(err.into());
                }
                pairing_start_for_state(workflow.state())
            })
            .await?;

        let code = if prompt.requires_connection_confirmation {
            "PAIRING_CONFIRMATION_REQUIRED"
        } else {
            "PAIRING_CODE_REQUIRED"
        };
        self.push(WorkflowEventKind::PairingPrompt, code, &prompt.message)
            .await;
        Ok(prompt)
    }

    #[uniffi::method]
    pub async fn pairing_submit_code(&self, code: String) -> Result<PairingProgress, HWCoreError> {
        self.progress("PAIRING_SUBMIT_CODE_START", "Submitting pairing code")
            .await;
        let progress = self
            .with_workflow(async |workflow| pairing_submit_code_for_workflow(workflow, code).await)
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("PAIRING_COMPLETE", &progress.message).await;
        Ok(progress)
    }

    #[uniffi::method]
    pub async fn pairing_confirm_connection(&self) -> Result<PairingProgress, HWCoreError> {
        self.progress(
            "PAIRING_CONFIRM_CONNECTION_START",
            "Confirming paired connection with device",
        )
        .await;
        let progress = self
            .with_workflow(async |workflow| pairing_confirm_connection_for_workflow(workflow).await)
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("PAIRING_CONFIRM_CONNECTION_OK", &progress.message)
            .await;
        Ok(progress)
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        self.progress("CREATE_SESSION_START", "Creating wallet session")
            .await;
        self.confirmation_possible("Confirm on device if prompted during session creation")
            .await;
        self.with_workflow(async |workflow| {
            Ok(workflow
                .create_session(passphrase, on_device, derive_cardano)
                .await?)
        })
        .await?;
        *self.session_ready.lock().await = true;
        self.push(
            WorkflowEventKind::Ready,
            "SESSION_READY",
            "Wallet session created",
        )
        .await;
        Ok(())
    }

    #[uniffi::method]
    pub async fn get_address(
        &self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError> {
        self.progress("GET_ADDRESS_START", "Requesting address from device")
            .await;
        let response = self
            .with_workflow(async |workflow| get_address_for_workflow(workflow, request).await)
            .await?;
        self.progress("GET_ADDRESS_OK", "Address received").await;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn get_nonce(&self) -> Result<String, HWCoreError> {
        self.progress(
            "GET_NONCE_START",
            "Requesting payment-request nonce from device",
        )
        .await;
        let response = self
            .with_workflow(async |workflow| get_nonce_for_workflow(workflow).await)
            .await?;
        self.progress("GET_NONCE_OK", "Payment-request nonce received")
            .await;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn sign_tx(&self, request: SignTxRequest) -> Result<SignTxResult, HWCoreError> {
        self.progress(
            "SIGN_TX_START",
            "Requesting transaction signature from device",
        )
        .await;
        self.confirmation_possible("Confirm on device if prompted during signing")
            .await;
        let response = self
            .with_workflow(async |workflow| sign_tx_for_workflow(workflow, request).await)
            .await?;
        self.progress("SIGN_TX_OK", "Transaction signed").await;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn sign_message(
        &self,
        request: SignMessageRequest,
    ) -> Result<SignMessageResult, HWCoreError> {
        self.progress(
            "SIGN_MESSAGE_START",
            "Requesting message signature from device",
        )
        .await;
        self.confirmation_possible("Confirm on device if prompted during message signing")
            .await;
        let response = self
            .with_workflow(async |workflow| sign_message_for_workflow(workflow, request).await)
            .await?;
        self.progress("SIGN_MESSAGE_OK", "Message signed").await;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn sign_typed_data(
        &self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResult, HWCoreError> {
        self.progress(
            "SIGN_TYPED_DATA_START",
            "Requesting typed-data signature from device",
        )
        .await;
        self.confirmation_possible("Confirm on device if prompted during typed-data signing")
            .await;
        let response = self
            .with_workflow(async |workflow| sign_typed_data_for_workflow(workflow, request).await)
            .await?;
        self.progress("SIGN_TYPED_DATA_OK", "Typed data signed")
            .await;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn abort(&self) -> Result<(), HWCoreError> {
        let mut workflow = self.workflow.lock().await;
        workflow.abort().await?;
        drop(workflow);
        *self.session_ready.lock().await = false;
        Ok(())
    }

    #[uniffi::method]
    pub async fn next_event(
        &self,
        timeout_ms: Option<u64>,
    ) -> Result<Option<WorkflowEvent>, HWCoreError> {
        loop {
            let maybe_event = {
                let mut events = self.events.lock().await;
                events.pop_front()
            };
            if maybe_event.is_some() {
                return Ok(maybe_event);
            }

            let notified = self.notify.notified();
            if let Some(timeout_ms) = timeout_ms {
                if timeout(Duration::from_millis(timeout_ms), notified)
                    .await
                    .is_err()
                {
                    return Ok(None);
                }
            } else {
                notified.await;
            }
        }
    }
}

fn session_state_for(
    workflow: &ThpWorkflow<BleBackend>,
    phase: WalletSessionPhase,
) -> Result<SessionState, HWCoreError> {
    let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
        Some(pairing_start_for_state(workflow.state())?.message)
    } else {
        None
    };
    Ok(build_session_state(phase, prompt_message))
}

impl BleWorkflowHandle {
    /// Runs `op` under the workflow lock and reports its failure as an error event.
    async fn with_workflow<T>(
        &self,
        op: impl AsyncFnOnce(&mut ThpWorkflow<BleBackend>) -> Result<T, HWCoreError>,
    ) -> Result<T, HWCoreError> {
        let result = {
            let mut workflow = self.workflow.lock().await;
            op(&mut workflow).await
        };
        if let Err(err) = &result {
            self.push_error_event(err).await;
        }
        result
    }

    pub(super) async fn push(&self, kind: WorkflowEventKind, code: &str, message: &str) {
        self.push_event(WorkflowEvent {
            kind,
            code: code.to_string(),
            message: message.to_string(),
        })
        .await;
    }

    async fn progress(&self, code: &str, message: &str) {
        self.push(WorkflowEventKind::Progress, code, message).await;
    }

    async fn confirmation_possible(&self, message: &str) {
        self.push(
            WorkflowEventKind::ButtonRequest,
            "DEVICE_CONFIRMATION_POSSIBLE",
            message,
        )
        .await;
    }

    async fn push_session_state_event(&self, state: &SessionState) {
        match (&state.phase, &state.prompt_message) {
            (WalletSessionPhase::Ready, _) => {
                self.push(
                    WorkflowEventKind::Ready,
                    "SESSION_READY",
                    "BLE workflow is authenticated and session-ready",
                )
                .await;
            }
            (WalletSessionPhase::NeedsPairingCode, Some(message)) => {
                self.push(
                    WorkflowEventKind::PairingPrompt,
                    "PAIRING_CODE_REQUIRED",
                    message,
                )
                .await;
            }
            _ => {}
        }
    }

    async fn create_channel(&self) -> Result<(), HWCoreError> {
        self.progress("CREATE_CHANNEL_START", "Creating THP channel")
            .await;
        self.with_workflow(async |workflow| Ok(workflow.create_channel().await?))
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("CREATE_CHANNEL_OK", "THP channel created")
            .await;
        Ok(())
    }

    async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.progress("HANDSHAKE_START", "Performing THP handshake")
            .await;
        let needs_pairing = self
            .with_workflow(async |workflow| {
                workflow.handshake(try_to_unlock).await?;
                Ok(workflow.state().phase() == Phase::Pairing && !workflow.state().is_paired())
            })
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("HANDSHAKE_OK", "THP handshake complete")
            .await;
        if needs_pairing {
            self.push(
                WorkflowEventKind::PairingPrompt,
                "PAIRING_REQUIRED",
                "Pairing interaction is required (code-entry expected)",
            )
            .await;
        }
        Ok(())
    }
}
