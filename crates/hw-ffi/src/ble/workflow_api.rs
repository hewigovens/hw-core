use super::*;

#[uniffi::export(async_runtime = "tokio")]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn session_state(&self) -> Result<SessionState, HWCoreError> {
        let ready = *self.session_ready.lock().await;
        let workflow = self.workflow.lock().await;
        let phase = session_phase(workflow.state(), ready);
        let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
            Some(pairing_start_for_state(workflow.state())?.message)
        } else {
            None
        };
        Ok(build_session_state(phase, prompt_message))
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
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIR_ONLY_START".to_string(),
            message: "Advancing workflow to paired state".to_string(),
        })
        .await;

        let mut workflow = self.workflow.lock().await;
        let policy = retry_policy.unwrap_or_default();
        let result = advance_to_paired_with_policy(&mut workflow, try_to_unlock, &policy).await;
        let mapped = match result {
            Ok(phase) => {
                let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
                    Some(pairing_start_for_state(workflow.state())?.message)
                } else {
                    None
                };
                Ok(build_session_state(phase, prompt_message))
            }
            Err(err) => Err(HWCoreError::from(err)),
        };
        drop(workflow);

        *self.session_ready.lock().await = false;

        match mapped {
            Ok(state) => {
                if matches!(state.phase, WalletSessionPhase::NeedsPairingCode)
                    && let Some(message) = &state.prompt_message
                {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::PairingPrompt,
                        code: "PAIRING_CODE_REQUIRED".to_string(),
                        message: message.clone(),
                    })
                    .await;
                }
                Ok(state)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
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
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CONNECT_READY_START".to_string(),
            message: "Advancing workflow to session-ready state".to_string(),
        })
        .await;

        let mut ready = *self.session_ready.lock().await;
        let options = bootstrap_options(try_to_unlock, retry_policy);

        let mut workflow = self.workflow.lock().await;
        let result = advance_session_bootstrap(&mut workflow, &mut ready, &options).await;
        let mapped = match result {
            Ok(phase) => {
                let prompt_message = if matches!(phase, WalletSessionPhase::NeedsPairingCode) {
                    Some(pairing_start_for_state(workflow.state())?.message)
                } else {
                    None
                };
                Ok(build_session_state(phase, prompt_message))
            }
            Err(err) => Err(HWCoreError::from(err)),
        };
        drop(workflow);

        *self.session_ready.lock().await = ready;

        match mapped {
            Ok(state) => {
                if matches!(state.phase, WalletSessionPhase::Ready) {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::Ready,
                        code: "SESSION_READY".to_string(),
                        message: "BLE workflow is authenticated and session-ready".to_string(),
                    })
                    .await;
                } else if matches!(state.phase, WalletSessionPhase::NeedsPairingCode)
                    && let Some(message) = &state.prompt_message
                {
                    self.push_event(WorkflowEvent {
                        kind: WorkflowEventKind::PairingPrompt,
                        code: "PAIRING_CODE_REQUIRED".to_string(),
                        message: message.clone(),
                    })
                    .await;
                }
                Ok(state)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn create_channel(&self) -> Result<HandshakeCache, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_CHANNEL_START".to_string(),
            message: "Creating THP channel".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow.create_channel().await {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let cache = workflow.state().handshake_cache().cloned().ok_or_else(|| {
            HWCoreError::Workflow("handshake cache missing after create_channel".to_string())
        })?;
        drop(workflow);
        *self.session_ready.lock().await = false;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_CHANNEL_OK".to_string(),
            message: "THP channel created".to_string(),
        })
        .await;
        Ok(cache)
    }

    #[uniffi::method]
    pub async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "HANDSHAKE_START".to_string(),
            message: "Performing THP handshake".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow.handshake(try_to_unlock).await {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let state = workflow.state().phase();
        let is_paired = workflow.state().is_paired();
        drop(workflow);
        *self.session_ready.lock().await = false;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "HANDSHAKE_OK".to_string(),
            message: "THP handshake complete".to_string(),
        })
        .await;
        if matches!(state, Phase::Pairing) && !is_paired {
            self.push_event(WorkflowEvent {
                kind: WorkflowEventKind::PairingPrompt,
                code: "PAIRING_REQUIRED".to_string(),
                message: "Pairing interaction is required (code-entry expected)".to_string(),
            })
            .await;
        }
        Ok(())
    }

    #[uniffi::method]
    pub async fn prepare_channel_and_handshake(
        &self,
        try_to_unlock: bool,
    ) -> Result<SessionHandshakeState, HWCoreError> {
        self.create_channel().await?;
        self.handshake(try_to_unlock).await?;

        let state = self.state().await;
        match state.phase {
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
        let mut workflow = self.workflow.lock().await;
        if workflow.state().phase() == Phase::Pairing
            && !workflow.state().is_paired()
            && let Err(err) = workflow.pairing(None).await
            && !matches!(err, ThpWorkflowError::PairingInteractionRequired)
        {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        let prompt = pairing_start_for_state(workflow.state())?;
        drop(workflow);

        let code = if prompt.requires_connection_confirmation {
            "PAIRING_CONFIRMATION_REQUIRED"
        } else {
            "PAIRING_CODE_REQUIRED"
        };
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::PairingPrompt,
            code: code.to_string(),
            message: prompt.message.clone(),
        })
        .await;
        Ok(prompt)
    }

    #[uniffi::method]
    pub async fn pairing_submit_code(&self, code: String) -> Result<PairingProgress, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIRING_SUBMIT_CODE_START".to_string(),
            message: "Submitting pairing code".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = pairing_submit_code_for_workflow(&mut workflow, code).await;
        drop(workflow);

        match result {
            Ok(progress) => {
                *self.session_ready.lock().await = false;
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "PAIRING_COMPLETE".to_string(),
                    message: progress.message.clone(),
                })
                .await;
                Ok(progress)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn pairing_confirm_connection(&self) -> Result<PairingProgress, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "PAIRING_CONFIRM_CONNECTION_START".to_string(),
            message: "Confirming paired connection with device".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = pairing_confirm_connection_for_workflow(&mut workflow).await;
        drop(workflow);

        match result {
            Ok(progress) => {
                *self.session_ready.lock().await = false;
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "PAIRING_CONFIRM_CONNECTION_OK".to_string(),
                    message: progress.message.clone(),
                })
                .await;
                Ok(progress)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "CREATE_SESSION_START".to_string(),
            message: "Creating wallet session".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during session creation".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        if let Err(err) = workflow
            .create_session(passphrase, on_device, derive_cardano)
            .await
        {
            let ffi_err = HWCoreError::from(err);
            drop(workflow);
            self.push_error_event(&ffi_err).await;
            return Err(ffi_err);
        }
        drop(workflow);
        *self.session_ready.lock().await = true;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Ready,
            code: "SESSION_READY".to_string(),
            message: "Wallet session created".to_string(),
        })
        .await;
        Ok(())
    }

    #[uniffi::method]
    pub async fn prepare_ready_session(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.prepare_ready_session_with_policy(try_to_unlock, None)
            .await
    }

    #[uniffi::method]
    pub async fn prepare_ready_session_with_policy(
        &self,
        try_to_unlock: bool,
        retry_policy: Option<SessionRetryPolicy>,
    ) -> Result<(), HWCoreError> {
        match self
            .connect_ready_with_policy(try_to_unlock, retry_policy)
            .await?
        {
            SessionState {
                phase: WalletSessionPhase::Ready,
                ..
            } => Ok(()),
            SessionState {
                phase: WalletSessionPhase::NeedsPairingCode,
                ..
            } => Err(HWCoreError::Workflow(
                "pairing interaction required before session can be prepared".to_string(),
            )),
            state => Err(HWCoreError::Workflow(format!(
                "unexpected workflow step after connect_ready: {:?}",
                state.phase
            ))),
        }
    }

    #[uniffi::method]
    pub async fn get_address(
        &self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "GET_ADDRESS_START".to_string(),
            message: "Requesting address from device".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = get_address_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "GET_ADDRESS_OK".to_string(),
                    message: "Address received".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn sign_tx(&self, request: SignTxRequest) -> Result<SignTxResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "SIGN_TX_START".to_string(),
            message: "Requesting transaction signature from device".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during signing".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = sign_tx_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "SIGN_TX_OK".to_string(),
                    message: "Transaction signed".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn sign_message(
        &self,
        request: SignMessageRequest,
    ) -> Result<SignMessageResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "SIGN_MESSAGE_START".to_string(),
            message: "Requesting message signature from device".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during message signing".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = sign_message_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "SIGN_MESSAGE_OK".to_string(),
                    message: "Message signed".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
    }

    #[uniffi::method]
    pub async fn sign_typed_data(
        &self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResult, HWCoreError> {
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::Progress,
            code: "SIGN_TYPED_DATA_START".to_string(),
            message: "Requesting typed-data signature from device".to_string(),
        })
        .await;
        self.push_event(WorkflowEvent {
            kind: WorkflowEventKind::ButtonRequest,
            code: "DEVICE_CONFIRMATION_POSSIBLE".to_string(),
            message: "Confirm on device if prompted during typed-data signing".to_string(),
        })
        .await;
        let mut workflow = self.workflow.lock().await;
        let result = sign_typed_data_for_workflow(&mut workflow, request).await;
        drop(workflow);

        match result {
            Ok(response) => {
                self.push_event(WorkflowEvent {
                    kind: WorkflowEventKind::Progress,
                    code: "SIGN_TYPED_DATA_OK".to_string(),
                    message: "Typed data signed".to_string(),
                })
                .await;
                Ok(response)
            }
            Err(err) => {
                self.push_error_event(&err).await;
                Err(err)
            }
        }
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
    pub async fn state(&self) -> ThpState {
        let workflow = self.workflow.lock().await;
        ThpState::from(workflow.state())
    }

    #[uniffi::method]
    pub async fn host_config(&self) -> HostConfig {
        let workflow = self.workflow.lock().await;
        workflow.host_config().clone().into()
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
