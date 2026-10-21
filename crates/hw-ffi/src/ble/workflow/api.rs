use hw_wallet::ble::{BootstrapTarget, SessionBootstrap, SessionBootstrapOptions};
use trezor_connect::thp::Phase;

use super::BleWorkflowHandle;
use super::pairing_flow::PairingFlow;
use super::wallet_requests::WalletRequests;
use crate::ble::bootstrap_options::SessionBootstrapOptionsExt;
use crate::errors::HWCoreError;
use crate::types::{
    AddressResult, BitcoinSignTxRequest, DeviceFeatures, GetAddressRequest, PairingMethod,
    PairingProgress, PairingPrompt, SessionHandshakeState, SessionPhase, SessionRetryPolicy,
    SessionState, SessionStateExt, SignMessageRequest, SignMessageResult, SignTxRequest,
    SignTxResult, SignTypedDataRequest, SignTypedDataResult, WorkflowEvent, WorkflowEventKind,
};

#[uniffi::export(async_runtime = "tokio")]
impl BleWorkflowHandle {
    #[uniffi::method]
    pub async fn session_state(&self) -> Result<SessionState, HWCoreError> {
        // Read readiness under the workflow lock: with_workflow resets both together on channel loss.
        let workflow = self.workflow.lock().await;
        let ready = *self.session_ready.lock().await;
        SessionState::with_prompt(
            SessionPhase::from_state(workflow.state(), ready),
            workflow.state(),
        )
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
        self.progress("PAIR_ONLY_START", "Advancing workflow to paired state");
        let options = SessionBootstrapOptions::from_ffi(try_to_unlock, retry_policy);
        let result = self
            .with_workflow(async |workflow| {
                let phase = workflow
                    .advance_session_bootstrap(false, BootstrapTarget::Paired, &options)
                    .await?;
                SessionState::with_pairing_prompt(phase, workflow.state())
            })
            .await;
        *self.session_ready.lock().await = false;
        let (state, prompt) = result?;
        self.push_session_state_event(&state, prompt.as_ref());
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
        );
        let ready = *self.session_ready.lock().await;
        let options = SessionBootstrapOptions::from_ffi(try_to_unlock, retry_policy);
        let state = self
            .with_workflow(async |workflow| {
                let phase = workflow
                    .advance_session_bootstrap(ready, BootstrapTarget::Session, &options)
                    .await?;
                SessionState::with_pairing_prompt(phase, workflow.state())
            })
            .await?;
        let (state, prompt) = state;
        *self.session_ready.lock().await = matches!(state.phase, SessionPhase::Ready);
        self.push_session_state_event(&state, prompt.as_ref());
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
            .with_workflow(async |workflow| workflow.start_pairing().await)
            .await?;

        self.push_pairing_prompt(&prompt);
        Ok(prompt)
    }

    #[uniffi::method]
    pub async fn pairing_submit_code(&self, code: String) -> Result<PairingProgress, HWCoreError> {
        self.progress("PAIRING_SUBMIT_CODE_START", "Submitting pairing code");
        let progress = self
            .with_workflow(async |workflow| workflow.submit_pairing_code(code).await)
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("PAIRING_COMPLETE", &progress.message);
        Ok(progress)
    }

    /// Switches a started pairing to QR code or NFC; the device then shows the QR code or
    /// waits for NFC. For NFC, hand the returned prompt's `nfc_data` to the device.
    #[uniffi::method]
    pub async fn pairing_select_method(
        &self,
        method: PairingMethod,
    ) -> Result<PairingPrompt, HWCoreError> {
        let prompt = self
            .with_workflow(async |workflow| {
                PairingFlow::select_pairing_method(workflow, method).await
            })
            .await?;
        self.push_pairing_prompt(&prompt);
        Ok(prompt)
    }

    /// Completes QR code pairing with the hex data scanned from the Trezor screen.
    #[uniffi::method]
    pub async fn pairing_submit_qr_tag(&self, tag: String) -> Result<PairingProgress, HWCoreError> {
        self.submit_pairing_tag(PairingMethod::QrCode, tag).await
    }

    /// Completes NFC pairing with the hex tag read from the Trezor over NFC.
    #[uniffi::method]
    pub async fn pairing_submit_nfc_tag(
        &self,
        tag: String,
    ) -> Result<PairingProgress, HWCoreError> {
        self.submit_pairing_tag(PairingMethod::Nfc, tag).await
    }

    #[uniffi::method]
    pub async fn pairing_confirm_connection(&self) -> Result<PairingProgress, HWCoreError> {
        self.progress(
            "PAIRING_CONFIRM_CONNECTION_START",
            "Confirming paired connection with device",
        );
        let progress = self
            .with_workflow(async |workflow| workflow.confirm_paired_connection().await)
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("PAIRING_CONFIRM_CONNECTION_OK", &progress.message);
        Ok(progress)
    }

    #[uniffi::method]
    pub async fn create_session(
        &self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<(), HWCoreError> {
        self.progress("CREATE_SESSION_START", "Creating wallet session");
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
        );
        Ok(())
    }

    #[uniffi::method]
    pub async fn get_address(
        &self,
        request: GetAddressRequest,
    ) -> Result<AddressResult, HWCoreError> {
        self.progress("GET_ADDRESS_START", "Requesting address from device");
        let response = self
            .with_workflow(async |workflow| workflow.request_address(request).await)
            .await?;
        self.progress("GET_ADDRESS_OK", "Address received");
        Ok(response)
    }

    /// Reads the device id, label, model, firmware version and passphrase settings.
    ///
    /// `device_id` is stable across phones and reconnects, unlike `BleDeviceInfo.id`.
    #[uniffi::method]
    pub async fn get_features(&self) -> Result<DeviceFeatures, HWCoreError> {
        self.with_workflow(async |workflow| Ok(workflow.get_features().await?))
            .await
    }

    #[uniffi::method]
    pub async fn get_nonce(&self) -> Result<String, HWCoreError> {
        self.progress(
            "GET_NONCE_START",
            "Requesting payment-request nonce from device",
        );
        let response = self
            .with_workflow(async |workflow| workflow.request_nonce().await)
            .await?;
        self.progress("GET_NONCE_OK", "Payment-request nonce received");
        Ok(response)
    }

    #[uniffi::method]
    pub async fn sign_tx(&self, request: SignTxRequest) -> Result<SignTxResult, HWCoreError> {
        self.progress(
            "SIGN_TX_START",
            "Requesting transaction signature from device",
        );
        let response = self
            .with_workflow(async |workflow| workflow.request_tx_signature(request).await)
            .await?;
        self.progress("SIGN_TX_OK", "Transaction signed");
        Ok(response)
    }

    /// Signs a Bitcoin transaction described by typed inputs, outputs and reference txs.
    #[uniffi::method]
    pub async fn sign_bitcoin_tx(
        &self,
        request: BitcoinSignTxRequest,
    ) -> Result<SignTxResult, HWCoreError> {
        self.progress(
            "SIGN_TX_START",
            "Requesting transaction signature from device",
        );
        let response = self
            .with_workflow(async |workflow| workflow.request_bitcoin_tx_signature(request).await)
            .await?;
        self.progress("SIGN_TX_OK", "Transaction signed");
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
        );
        let response = self
            .with_workflow(async |workflow| workflow.request_message_signature(request).await)
            .await?;
        self.progress("SIGN_MESSAGE_OK", "Message signed");
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
        );
        let response = self
            .with_workflow(async |workflow| workflow.request_typed_data_signature(request).await)
            .await?;
        self.progress("SIGN_TYPED_DATA_OK", "Typed data signed");
        Ok(response)
    }

    /// Cancels the prompt the device is showing for the running request, keeping the channel.
    ///
    /// The running call then fails with `HWCoreError::ActionCancelled` and the device returns
    /// to its home screen. Does nothing when no request is running.
    #[uniffi::method]
    pub fn cancel(&self) {
        if self.workflow.try_lock().is_err() {
            self.cancel.cancel();
        }
    }

    /// Tears down the THP channel and disconnects BLE; the next call needs a new handshake.
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
        Ok(self.next_queued_event(timeout_ms).await)
    }
}

impl BleWorkflowHandle {
    async fn submit_pairing_tag(
        &self,
        method: PairingMethod,
        tag: String,
    ) -> Result<PairingProgress, HWCoreError> {
        self.progress("PAIRING_SUBMIT_TAG_START", "Submitting pairing tag");
        let progress = self
            .with_workflow(async |workflow| {
                PairingFlow::submit_pairing_tag(workflow, method, tag).await
            })
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("PAIRING_COMPLETE", &progress.message);
        Ok(progress)
    }

    async fn create_channel(&self) -> Result<(), HWCoreError> {
        self.progress("CREATE_CHANNEL_START", "Creating THP channel");
        self.with_workflow(async |workflow| Ok(workflow.create_channel().await?))
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("CREATE_CHANNEL_OK", "THP channel created");
        Ok(())
    }

    async fn handshake(&self, try_to_unlock: bool) -> Result<(), HWCoreError> {
        self.progress("HANDSHAKE_START", "Performing THP handshake");
        let needs_pairing = self
            .with_workflow(async |workflow| {
                workflow.handshake(try_to_unlock).await?;
                Ok(workflow.state().phase() == Phase::Pairing && !workflow.state().is_paired())
            })
            .await?;
        *self.session_ready.lock().await = false;
        self.progress("HANDSHAKE_OK", "THP handshake complete");
        if needs_pairing {
            self.push(
                WorkflowEventKind::PairingPrompt,
                "PAIRING_REQUIRED",
                "Pairing interaction is required",
            );
        }
        Ok(())
    }
}
