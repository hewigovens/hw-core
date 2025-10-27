use std::sync::Arc;

use rand::RngCore;
use tracing::debug;

use super::{
    backend::ThpBackend,
    error::{Result, ThpWorkflowError},
    state::{HandshakeCache, HandshakeCredentials, Phase, ThpState},
    storage::{HostSnapshot, ThpStorage},
    types::{
        CreateChannelRequest, CreateSessionRequest, HandshakeCompletionRequest,
        HandshakeCompletionState, HandshakeInitRequest, HostConfig, PairingController,
        PairingDecision, PairingMethod, PairingPrompt, PairingTagRequest, SelectMethodRequest,
    },
};

pub struct ThpWorkflow<B> {
    backend: B,
    config: HostConfig,
    state: ThpState,
    rng: rand::rngs::ThreadRng,
    storage: Option<Arc<dyn ThpStorage>>,
}

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub fn new(backend: B, config: HostConfig) -> Self {
        Self {
            backend,
            config,
            state: ThpState::new(),
            rng: rand::thread_rng(),
            storage: None,
        }
    }

    pub async fn with_storage(
        backend: B,
        mut config: HostConfig,
        storage: Arc<dyn ThpStorage>,
    ) -> Result<Self> {
        let snapshot = storage.load().await.map_err(ThpWorkflowError::Storage)?;

        if let Some(static_key) = snapshot.static_key {
            config.static_key = Some(static_key);
        }
        if !snapshot.known_credentials.is_empty() {
            config.known_credentials = snapshot.known_credentials;
        }

        Ok(Self {
            backend,
            config,
            state: ThpState::new(),
            rng: rand::thread_rng(),
            storage: Some(storage),
        })
    }

    pub fn state(&self) -> &ThpState {
        &self.state
    }

    pub fn host_config(&self) -> &HostConfig {
        &self.config
    }

    pub fn into_parts(self) -> (B, HostConfig, ThpState) {
        (self.backend, self.config, self.state)
    }

    async fn persist_host_state(&self) -> Result<()> {
        if let Some(storage) = &self.storage {
            let snapshot = HostSnapshot {
                static_key: self.config.static_key.clone(),
                known_credentials: self.config.known_credentials.clone(),
            };
            storage
                .persist(&snapshot)
                .await
                .map_err(ThpWorkflowError::Storage)?;
        }
        Ok(())
    }

    pub async fn create_channel(&mut self) -> Result<()> {
        if self.state.phase() != Phase::Handshake {
            return Err(ThpWorkflowError::InvalidPhase);
        }

        let mut nonce = [0u8; 8];
        self.rng.fill_bytes(&mut nonce);
        let response = self
            .backend
            .create_channel(CreateChannelRequest { nonce })
            .await?;

        if response.nonce != nonce {
            return Err(ThpWorkflowError::NonceMismatch);
        }

        let available = response.properties.pairing_methods.clone();
        let host_supported = if self.config.pairing_methods.is_empty() {
            available.clone()
        } else {
            available
                .into_iter()
                .filter(|m| self.config.pairing_methods.contains(m))
                .collect::<Vec<_>>()
        };

        if host_supported.is_empty() {
            return Err(ThpWorkflowError::NoCommonPairingMethod);
        }

        let cache = HandshakeCache {
            channel: response.channel,
            handshake_hash: response.handshake_hash.clone(),
            pairing_methods: host_supported,
        };
        self.state.set_handshake_cache(cache);
        Ok(())
    }

    pub async fn handshake(&mut self, try_to_unlock: bool) -> Result<()> {
        let cache = self
            .state
            .handshake_cache()
            .ok_or(ThpWorkflowError::MissingHandshake)?;

        let request = HandshakeInitRequest {
            try_to_unlock,
            handshake_hash: cache.handshake_hash.clone(),
            pairing_methods: cache.pairing_methods.clone(),
            static_key: self.config.static_key.clone(),
            known_credentials: self.config.known_credentials.clone(),
        };

        let outcome = self.backend.handshake_init(request).await?;

        let creds = HandshakeCredentials {
            pairing_methods: outcome.pairing_methods.clone(),
            handshake_hash: outcome.handshake_hash.clone(),
            trezor_encrypted_static_pubkey: outcome.trezor_encrypted_static_pubkey.clone(),
            host_encrypted_static_pubkey: outcome.host_encrypted_static_pubkey.clone(),
            host_key: outcome.host_key.clone(),
            trezor_key: outcome.trezor_key.clone(),
            host_static_key: outcome.host_static_key.clone(),
            host_static_public_key: outcome.host_static_public_key.clone(),
            nfc_data: outcome.nfc_data.clone(),
            handshake_commitment: outcome.handshake_commitment.clone(),
            trezor_cpace_public_key: outcome.trezor_cpace_public_key.clone(),
            code_entry_challenge: outcome.code_entry_challenge.clone(),
            pairing_credentials: outcome.credentials.clone(),
            selected_credential: outcome.selected_credential.clone(),
        };

        self.config.static_key = Some(outcome.host_static_key.clone());
        self.config.known_credentials = outcome.credentials.clone();

        self.state.set_handshake_credentials(creds);
        if let Some(method) = outcome.pairing_methods.first() {
            self.state.set_pairing_method(*method);
        }
        self.state
            .set_pairing_credentials(outcome.credentials.clone());
        self.state.set_autoconnect_paired(
            outcome
                .selected_credential
                .as_ref()
                .is_some_and(|c| c.autoconnect),
        );

        let completion = self
            .backend
            .handshake_complete(HandshakeCompletionRequest {
                host_pubkey: outcome.host_encrypted_static_pubkey.clone(),
                encrypted_payload: outcome.encrypted_payload.clone(),
            })
            .await?;

        match completion.state {
            HandshakeCompletionState::RequiresPairing => {
                if let Some(selected) = outcome.selected_credential {
                    self.config
                        .known_credentials
                        .retain(|c| c.credential != selected.credential);
                }
                self.state.set_is_paired(false);
                self.state.set_phase(Phase::Pairing);
            }
            HandshakeCompletionState::Paired => {
                self.state.set_is_paired(true);
                self.state.set_phase(Phase::Paired);
            }
            HandshakeCompletionState::AutoPaired => {
                self.state.set_is_paired(true);
                self.state.set_phase(Phase::Paired);
                self.state.set_autoconnect_paired(true);
                self.backend.end_request().await?;
            }
        }

        self.persist_host_state().await?;
        Ok(())
    }

    pub async fn pairing(&mut self, controller: Option<&dyn PairingController>) -> Result<()> {
        match self.state.phase() {
            Phase::Paired => return Ok(()),
            Phase::Pairing => {}
            _ => return Err(ThpWorkflowError::InvalidPhase),
        }

        let handshake = self
            .state
            .handshake_credentials()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?;

        if self.state.is_paired()
            && handshake
                .pairing_methods
                .first()
                .copied()
                .unwrap_or(PairingMethod::SkipPairing)
                != PairingMethod::SkipPairing
        {
            let response = self
                .backend
                .credential_request(super::types::CredentialRequest {
                    autoconnect: false,
                    host_static_public_key: handshake.host_static_public_key.clone(),
                    credential: handshake
                        .pairing_credentials
                        .first()
                        .map(|c| c.credential.clone()),
                })
                .await?;

            let new_cred = super::types::KnownCredential {
                credential: response.credential.clone(),
                trezor_static_public_key: Some(response.trezor_static_public_key.clone()),
                autoconnect: response.autoconnect,
            };
            self.config
                .known_credentials
                .retain(|c| c.credential != new_cred.credential);
            self.config.known_credentials.push(new_cred.clone());
            self.state.set_pairing_credentials(vec![new_cred]);
            self.backend.end_request().await?;
            self.state.set_phase(Phase::Paired);
            self.persist_host_state().await?;
            return Ok(());
        }

        let controller = controller.ok_or(ThpWorkflowError::PairingInteractionRequired)?;

        self.backend
            .pairing_request(super::types::PairingRequest {
                host_name: self.config.host_name.clone(),
                app_name: self.config.app_name.clone(),
            })
            .await?;

        let mut current_method = self
            .state
            .pairing_method()
            .unwrap_or_else(|| handshake.pairing_methods[0]);
        self.state.set_pairing_method(current_method);

        let mut select_response = self
            .backend
            .select_pairing_method(SelectMethodRequest {
                method: current_method,
            })
            .await?;

        loop {
            match select_response {
                super::types::SelectMethodResponse::End => {
                    self.state.set_is_paired(true);
                    self.state.set_phase(Phase::Paired);
                    self.backend.end_request().await?;
                    return Ok(());
                }
                super::types::SelectMethodResponse::CodeEntryCommitment { ref commitment } => {
                    let prompt = PairingPrompt {
                        available_methods: handshake.pairing_methods.clone(),
                        selected_method: current_method,
                        nfc_data: None,
                    };
                    let decision = controller
                        .on_prompt(prompt)
                        .await
                        .map_err(ThpWorkflowError::PairingController)?;

                    match decision {
                        PairingDecision::SwitchMethod(method) => {
                            current_method = method;
                            self.state.set_pairing_method(method);
                            select_response = self
                                .backend
                                .select_pairing_method(SelectMethodRequest { method })
                                .await?;
                            continue;
                        }
                        PairingDecision::SubmitTag { method, tag } => {
                            if method != current_method {
                                current_method = method;
                                self.state.set_pairing_method(method);
                                select_response = self
                                    .backend
                                    .select_pairing_method(SelectMethodRequest { method })
                                    .await?;
                                continue;
                            }

                            self.state.update_handshake_credentials(|creds| {
                                creds.handshake_commitment = Some(commitment.clone());
                            });

                            let request = PairingTagRequest::CodeEntry {
                                code: tag,
                                handshake_hash: handshake.handshake_hash.clone(),
                                commitment: Some(commitment.clone()),
                                challenge: handshake.code_entry_challenge.clone(),
                                trezor_cpace_public_key: handshake.trezor_cpace_public_key.clone(),
                            };
                            match self.backend.send_pairing_tag(request).await? {
                                super::types::PairingTagResponse::Accepted => {
                                    break;
                                }
                                super::types::PairingTagResponse::Retry(reason) => {
                                    debug!("code entry retry requested: {reason}");
                                    continue;
                                }
                            }
                        }
                    }
                }
                super::types::SelectMethodResponse::PairingPreparationsFinished {
                    ref nfc_data,
                } => {
                    let prompt = PairingPrompt {
                        available_methods: handshake.pairing_methods.clone(),
                        selected_method: current_method,
                        nfc_data: nfc_data.clone().or(handshake.nfc_data.clone()),
                    };
                    let decision = controller
                        .on_prompt(prompt)
                        .await
                        .map_err(ThpWorkflowError::PairingController)?;

                    match decision {
                        PairingDecision::SwitchMethod(method) => {
                            current_method = method;
                            self.state.set_pairing_method(method);
                            select_response = self
                                .backend
                                .select_pairing_method(SelectMethodRequest { method })
                                .await?;
                            continue;
                        }
                        PairingDecision::SubmitTag { method, tag } => {
                            if method != current_method {
                                current_method = method;
                                self.state.set_pairing_method(method);
                                select_response = self
                                    .backend
                                    .select_pairing_method(SelectMethodRequest { method })
                                    .await?;
                                continue;
                            }

                            self.state.update_handshake_credentials(|creds| {
                                if let Some(data) = nfc_data.clone() {
                                    creds.nfc_data = Some(data);
                                }
                            });

                            let request = match method {
                                PairingMethod::QrCode => PairingTagRequest::QrCode {
                                    handshake_hash: handshake.handshake_hash.clone(),
                                    tag,
                                },
                                PairingMethod::Nfc => PairingTagRequest::Nfc {
                                    handshake_hash: handshake.handshake_hash.clone(),
                                    tag,
                                },
                                PairingMethod::CodeEntry => continue,
                                PairingMethod::SkipPairing => continue,
                            };

                            match self.backend.send_pairing_tag(request).await? {
                                super::types::PairingTagResponse::Accepted => {
                                    break;
                                }
                                super::types::PairingTagResponse::Retry(reason) => {
                                    debug!("pairing tag retry requested: {reason}");
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
        }

        let credential_resp = self
            .backend
            .credential_request(super::types::CredentialRequest {
                autoconnect: false,
                host_static_public_key: handshake.host_static_public_key.clone(),
                credential: handshake
                    .pairing_credentials
                    .first()
                    .map(|c| c.credential.clone()),
            })
            .await?;

        let new_cred = super::types::KnownCredential {
            credential: credential_resp.credential.clone(),
            trezor_static_public_key: Some(credential_resp.trezor_static_public_key.clone()),
            autoconnect: credential_resp.autoconnect,
        };

        self.config
            .known_credentials
            .retain(|c| c.credential != new_cred.credential);
        self.config.known_credentials.push(new_cred.clone());
        self.state.set_pairing_credentials(vec![new_cred]);
        self.state.set_is_paired(true);
        self.state.set_phase(Phase::Paired);
        self.backend.end_request().await?;
        self.persist_host_state().await?;

        Ok(())
    }

    pub async fn create_session(
        &mut self,
        passphrase: Option<String>,
        on_device: bool,
        derive_cardano: bool,
    ) -> Result<()> {
        self.backend
            .create_new_session(CreateSessionRequest {
                passphrase,
                on_device,
                derive_cardano,
            })
            .await?;
        Ok(())
    }

    pub async fn abort(&mut self) -> Result<()> {
        self.backend.abort().await?;
        self.state.reset();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::{BackendError, BackendResult, ThpBackend};
    use super::*;
    use crate::thp::types::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;

    struct MockBackend {
        create_channel_resp: CreateChannelResponse,
        handshake_outcome: HandshakeInitOutcome,
        handshake_state: HandshakeCompletionState,
        credential_response: Option<CredentialResponse>,
        select_responses: Mutex<VecDeque<SelectMethodResponse>>,
        tag_response: Mutex<Option<PairingTagResponse>>,
        pairing_requested: Mutex<bool>,
        end_called: Mutex<bool>,
    }

    impl MockBackend {
        fn autopair() -> Self {
            Self {
                create_channel_resp: CreateChannelResponse {
                    nonce: [1u8; 8],
                    channel: 1,
                    handshake_hash: b"hash".to_vec(),
                    properties: ThpProperties {
                        pairing_methods: vec![PairingMethod::SkipPairing],
                    },
                },
                handshake_outcome: HandshakeInitOutcome {
                    host_encrypted_static_pubkey: vec![1, 2, 3],
                    encrypted_payload: vec![4, 5, 6],
                    trezor_encrypted_static_pubkey: vec![7, 8, 9],
                    handshake_hash: b"hash".to_vec(),
                    host_key: vec![10],
                    trezor_key: vec![11],
                    host_static_key: vec![12],
                    host_static_public_key: vec![13],
                    pairing_methods: vec![PairingMethod::SkipPairing],
                    credentials: vec![KnownCredential {
                        credential: "cred1".into(),
                        trezor_static_public_key: Some(vec![0x11; 32]),
                        autoconnect: true,
                    }],
                    selected_credential: Some(KnownCredential {
                        credential: "cred1".into(),
                        trezor_static_public_key: Some(vec![0x11; 32]),
                        autoconnect: true,
                    }),
                    nfc_data: None,
                    handshake_commitment: None,
                    trezor_cpace_public_key: None,
                    code_entry_challenge: None,
                },
                handshake_state: HandshakeCompletionState::AutoPaired,
                credential_response: Some(CredentialResponse {
                    trezor_static_public_key: vec![0x11; 32],
                    credential: "cred1".into(),
                    autoconnect: true,
                }),
                select_responses: Mutex::new(VecDeque::new()),
                tag_response: Mutex::new(None),
                pairing_requested: Mutex::new(false),
                end_called: Mutex::new(false),
            }
        }

        fn pairing_flow() -> Self {
            let mut select = VecDeque::new();
            select.push_back(SelectMethodResponse::PairingPreparationsFinished { nfc_data: None });
            Self {
                create_channel_resp: CreateChannelResponse {
                    nonce: [2u8; 8],
                    channel: 2,
                    handshake_hash: b"pair".to_vec(),
                    properties: ThpProperties {
                        pairing_methods: vec![PairingMethod::QrCode],
                    },
                },
                handshake_outcome: HandshakeInitOutcome {
                    host_encrypted_static_pubkey: vec![1, 2, 3],
                    encrypted_payload: vec![4, 5, 6],
                    trezor_encrypted_static_pubkey: vec![7, 8, 9],
                    handshake_hash: b"pair".to_vec(),
                    host_key: vec![10],
                    trezor_key: vec![11],
                    host_static_key: vec![12],
                    host_static_public_key: vec![13],
                    pairing_methods: vec![PairingMethod::QrCode],
                    credentials: vec![],
                    selected_credential: None,
                    nfc_data: None,
                    handshake_commitment: None,
                    trezor_cpace_public_key: None,
                    code_entry_challenge: None,
                },
                handshake_state: HandshakeCompletionState::RequiresPairing,
                credential_response: Some(CredentialResponse {
                    trezor_static_public_key: vec![0x22; 32],
                    credential: "new-cred".into(),
                    autoconnect: false,
                }),
                select_responses: Mutex::new(select),
                tag_response: Mutex::new(Some(PairingTagResponse::Accepted)),
                pairing_requested: Mutex::new(false),
                end_called: Mutex::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl ThpBackend for MockBackend {
        async fn create_channel(
            &mut self,
            request: CreateChannelRequest,
        ) -> BackendResult<CreateChannelResponse> {
            let mut resp = self.create_channel_resp.clone();
            resp.nonce = request.nonce;
            Ok(resp)
        }

        async fn handshake_init(
            &mut self,
            _request: HandshakeInitRequest,
        ) -> BackendResult<HandshakeInitOutcome> {
            Ok(self.handshake_outcome.clone())
        }

        async fn handshake_complete(
            &mut self,
            _request: HandshakeCompletionRequest,
        ) -> BackendResult<HandshakeCompletionResponse> {
            Ok(HandshakeCompletionResponse {
                state: self.handshake_state,
            })
        }

        async fn pairing_request(
            &mut self,
            _request: PairingRequest,
        ) -> BackendResult<PairingRequestApproved> {
            *self.pairing_requested.lock() = true;
            Ok(PairingRequestApproved)
        }

        async fn select_pairing_method(
            &mut self,
            _request: SelectMethodRequest,
        ) -> BackendResult<SelectMethodResponse> {
            self.select_responses
                .lock()
                .pop_front()
                .ok_or_else(|| BackendError::Device("no more select responses".into()))
        }

        async fn send_pairing_tag(
            &mut self,
            _request: PairingTagRequest,
        ) -> BackendResult<PairingTagResponse> {
            self.tag_response
                .lock()
                .take()
                .ok_or_else(|| BackendError::Device("unexpected tag".into()))
        }

        async fn credential_request(
            &mut self,
            _request: CredentialRequest,
        ) -> BackendResult<CredentialResponse> {
            self.credential_response
                .clone()
                .ok_or_else(|| BackendError::Device("no credential response".into()))
        }

        async fn end_request(&mut self) -> BackendResult<()> {
            *self.end_called.lock() = true;
            Ok(())
        }

        async fn create_new_session(
            &mut self,
            _request: CreateSessionRequest,
        ) -> BackendResult<CreateSessionResponse> {
            Ok(CreateSessionResponse)
        }

        async fn abort(&mut self) -> BackendResult<()> {
            Ok(())
        }
    }

    struct TestController;

    #[async_trait::async_trait]
    impl PairingController for TestController {
        async fn on_prompt(
            &self,
            prompt: PairingPrompt,
        ) -> std::result::Result<PairingDecision, String> {
            if prompt.available_methods.contains(&PairingMethod::QrCode) {
                Ok(PairingDecision::SubmitTag {
                    method: PairingMethod::QrCode,
                    tag: "deadbeef".into(),
                })
            } else {
                Err("no supported method".into())
            }
        }
    }

    #[tokio::test]
    async fn autopair_flow_sets_paired_state() {
        let backend = MockBackend::autopair();
        let mut workflow = ThpWorkflow::new(
            backend,
            HostConfig {
                pairing_methods: vec![PairingMethod::SkipPairing],
                known_credentials: vec![],
                static_key: None,
                host_name: "host".into(),
                app_name: "app".into(),
            },
        );

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();

        assert!(workflow.state().is_paired());
        assert_eq!(workflow.state().phase(), Phase::Paired);

        let (backend, _, state) = workflow.into_parts();
        assert!(state.is_paired());
        assert_eq!(state.phase(), Phase::Paired);
        assert!(*backend.end_called.lock());
    }

    #[tokio::test]
    async fn pairing_flow_with_controller() {
        let backend = MockBackend::pairing_flow();
        let controller = TestController;
        let mut workflow = ThpWorkflow::new(
            backend,
            HostConfig {
                pairing_methods: vec![PairingMethod::QrCode],
                known_credentials: vec![],
                static_key: None,
                host_name: "host".into(),
                app_name: "app".into(),
            },
        );

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();
        workflow
            .pairing(Some(&controller))
            .await
            .expect("pairing succeeds");

        assert!(workflow.state().is_paired());
        assert_eq!(workflow.state().phase(), Phase::Paired);

        let (backend, _, state) = workflow.into_parts();
        assert!(state.is_paired());
        assert!(*backend.pairing_requested.lock());
        assert!(*backend.end_called.lock());
    }
}
