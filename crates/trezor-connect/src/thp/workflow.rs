use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tracing::debug;

use super::{
    backend::ThpBackend,
    error::{Result, ThpWorkflowError},
    state::{HandshakeCache, HandshakeCredentials, Phase, ThpState},
    storage::{HostSnapshot, ThpStorage},
    types::{
        CodeEntryChallengeRequest, CreateChannelRequest, CreateSessionRequest, GetAddressRequest,
        GetAddressResponse, HandshakeCompletionRequest, HandshakeCompletionState,
        HandshakeInitRequest, HostConfig, PairingController, PairingDecision, PairingMethod,
        PairingPrompt, PairingTagRequest, SelectMethodRequest, SignTxRequest, SignTxResponse,
    },
};

pub struct ThpWorkflow<B> {
    backend: B,
    config: HostConfig,
    state: ThpState,
    rng: StdRng,
    storage: Option<Arc<dyn ThpStorage>>,
}

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub fn new(backend: B, config: HostConfig) -> Self {
        let mut os_rng = rand::rng();
        Self {
            backend,
            config,
            state: ThpState::new(),
            rng: StdRng::from_rng(&mut os_rng),
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
            rng: StdRng::from_rng(&mut rand::rng()),
            storage: Some(storage),
        })
    }

    pub fn state(&self) -> &ThpState {
        &self.state
    }

    pub fn host_config(&self) -> &HostConfig {
        &self.config
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
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
        self.rng.fill(&mut nonce);
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

        'pairing_flow: loop {
            match select_response {
                super::types::SelectMethodResponse::End => {
                    self.state.set_is_paired(true);
                    self.state.set_phase(Phase::Paired);
                    self.backend.end_request().await?;
                    return Ok(());
                }
                super::types::SelectMethodResponse::CodeEntryCommitment { ref commitment } => {
                    debug!(
                        "code-entry commitment received: commitment_len={}",
                        commitment.len(),
                    );

                    self.state.update_handshake_credentials(|creds| {
                        creds.handshake_commitment = Some(commitment.clone());
                    });

                    'code_entry: loop {
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
                            .code_entry_challenge(CodeEntryChallengeRequest {
                                challenge: challenge.clone(),
                            })
                            .await
                        {
                            Ok(response) => response,
                            Err(super::backend::BackendError::Device(reason)) => {
                                debug!(
                                    "code-entry challenge rejected by device: {reason}; requesting fresh commitment"
                                );
                                select_response = self
                                    .backend
                                    .select_pairing_method(SelectMethodRequest {
                                        method: current_method,
                                    })
                                    .await?;
                                continue 'pairing_flow;
                            }
                            Err(err) => return Err(err.into()),
                        };
                        debug!(
                            "code-entry: received ThpCodeEntryCpaceTrezor, public_key_len={}",
                            cpace_response.trezor_cpace_public_key.len()
                        );
                        self.state.update_handshake_credentials(|creds| {
                            creds.trezor_cpace_public_key =
                                Some(cpace_response.trezor_cpace_public_key.clone());
                        });

                        let prompt = PairingPrompt {
                            available_methods: handshake.pairing_methods.clone(),
                            selected_method: current_method,
                            nfc_data: None,
                        };
                        let decision = controller.on_prompt(prompt).await;
                        let decision = match decision {
                            Ok(v) => v,
                            Err(err) => return Err(ThpWorkflowError::PairingController(err)),
                        };

                        if let PairingDecision::SwitchMethod(method) = decision {
                            current_method = method;
                            self.state.set_pairing_method(method);
                            select_response = self
                                .backend
                                .select_pairing_method(SelectMethodRequest { method })
                                .await?;
                            continue 'pairing_flow;
                        }

                        let PairingDecision::SubmitTag { method, tag } = decision else {
                            continue 'code_entry;
                        };

                        if method != current_method {
                            current_method = method;
                            self.state.set_pairing_method(method);
                            select_response = self
                                .backend
                                .select_pairing_method(SelectMethodRequest { method })
                                .await?;
                            continue 'pairing_flow;
                        }

                        let current_handshake = self
                            .state
                            .handshake_credentials()
                            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?;
                        let request = PairingTagRequest::CodeEntry {
                            code: tag,
                            handshake_hash: current_handshake.handshake_hash.clone(),
                            commitment: current_handshake.handshake_commitment.clone(),
                            challenge: current_handshake.code_entry_challenge.clone(),
                            trezor_cpace_public_key: current_handshake
                                .trezor_cpace_public_key
                                .clone(),
                        };
                        match self.backend.send_pairing_tag(request).await? {
                            super::types::PairingTagResponse::Accepted { .. } => {
                                break 'code_entry;
                            }
                            super::types::PairingTagResponse::Retry(reason) => {
                                debug!(
                                    "code entry retry requested: {reason}; requesting fresh commitment"
                                );
                                select_response = self
                                    .backend
                                    .select_pairing_method(SelectMethodRequest {
                                        method: current_method,
                                    })
                                    .await?;
                                continue 'pairing_flow;
                            }
                        }
                    }

                    break;
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
                                super::types::PairingTagResponse::Accepted { .. } => {
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

    pub async fn get_address(&mut self, request: GetAddressRequest) -> Result<GetAddressResponse> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        self.backend.get_address(request).await.map_err(Into::into)
    }

    pub async fn sign_tx(&mut self, request: SignTxRequest) -> Result<SignTxResponse> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        self.backend.sign_tx(request).await.map_err(Into::into)
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
    use super::super::storage::{HostSnapshot, StorageError, ThpStorage};
    use super::*;
    use crate::thp::types::*;
    use parking_lot::Mutex;
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct MockBackend {
        create_channel_resp: CreateChannelResponse,
        handshake_outcome: HandshakeInitOutcome,
        handshake_state: HandshakeCompletionState,
        credential_response: Option<CredentialResponse>,
        select_responses: Mutex<VecDeque<SelectMethodResponse>>,
        tag_responses: Mutex<VecDeque<PairingTagResponse>>,
        code_entry_challenge_response: Option<CodeEntryChallengeResponse>,
        code_entry_challenge_requests: Mutex<Vec<CodeEntryChallengeRequest>>,
        tag_requests: Mutex<Vec<PairingTagRequest>>,
        last_tag_request: Mutex<Option<PairingTagRequest>>,
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
                        internal_model: "T2T1".into(),
                        model_variant: 0,
                        protocol_version_major: 1,
                        protocol_version_minor: 0,
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
                tag_responses: Mutex::new(VecDeque::new()),
                code_entry_challenge_response: None,
                code_entry_challenge_requests: Mutex::new(Vec::new()),
                tag_requests: Mutex::new(Vec::new()),
                last_tag_request: Mutex::new(None),
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
                        internal_model: "T2T1".into(),
                        model_variant: 0,
                        protocol_version_major: 1,
                        protocol_version_minor: 0,
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
                tag_responses: Mutex::new(VecDeque::from([PairingTagResponse::Accepted {
                    secret: vec![1, 2],
                }])),
                code_entry_challenge_response: None,
                code_entry_challenge_requests: Mutex::new(Vec::new()),
                tag_requests: Mutex::new(Vec::new()),
                last_tag_request: Mutex::new(None),
                pairing_requested: Mutex::new(false),
                end_called: Mutex::new(false),
            }
        }

        fn code_entry_flow() -> Self {
            let mut select = VecDeque::new();
            select.push_back(SelectMethodResponse::CodeEntryCommitment {
                commitment: vec![0xAA; 32],
            });
            Self {
                create_channel_resp: CreateChannelResponse {
                    nonce: [3u8; 8],
                    channel: 3,
                    handshake_hash: b"code-entry".to_vec(),
                    properties: ThpProperties {
                        internal_model: "T3W1".into(),
                        model_variant: 1,
                        protocol_version_major: 2,
                        protocol_version_minor: 0,
                        pairing_methods: vec![PairingMethod::CodeEntry],
                    },
                },
                handshake_outcome: HandshakeInitOutcome {
                    host_encrypted_static_pubkey: vec![1, 2, 3],
                    encrypted_payload: vec![4, 5, 6],
                    trezor_encrypted_static_pubkey: vec![7, 8, 9],
                    handshake_hash: b"code-entry".to_vec(),
                    host_key: vec![10],
                    trezor_key: vec![11],
                    host_static_key: vec![12],
                    host_static_public_key: vec![13],
                    pairing_methods: vec![PairingMethod::CodeEntry],
                    credentials: vec![],
                    selected_credential: None,
                    nfc_data: None,
                    handshake_commitment: None,
                    trezor_cpace_public_key: None,
                    code_entry_challenge: None,
                },
                handshake_state: HandshakeCompletionState::RequiresPairing,
                credential_response: Some(CredentialResponse {
                    trezor_static_public_key: vec![0x33; 32],
                    credential: "code-entry-cred".into(),
                    autoconnect: false,
                }),
                select_responses: Mutex::new(select),
                tag_responses: Mutex::new(VecDeque::from([PairingTagResponse::Accepted {
                    secret: vec![9, 9],
                }])),
                code_entry_challenge_response: Some(CodeEntryChallengeResponse {
                    trezor_cpace_public_key: vec![0x44; 32],
                }),
                code_entry_challenge_requests: Mutex::new(Vec::new()),
                tag_requests: Mutex::new(Vec::new()),
                last_tag_request: Mutex::new(None),
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

        async fn code_entry_challenge(
            &mut self,
            request: CodeEntryChallengeRequest,
        ) -> BackendResult<CodeEntryChallengeResponse> {
            self.code_entry_challenge_requests.lock().push(request);
            self.code_entry_challenge_response
                .clone()
                .ok_or_else(|| BackendError::Device("unexpected code entry challenge".into()))
        }

        async fn send_pairing_tag(
            &mut self,
            request: PairingTagRequest,
        ) -> BackendResult<PairingTagResponse> {
            self.tag_requests.lock().push(request.clone());
            *self.last_tag_request.lock() = Some(request);
            self.tag_responses
                .lock()
                .pop_front()
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

        async fn get_address(
            &mut self,
            request: GetAddressRequest,
        ) -> BackendResult<GetAddressResponse> {
            Ok(GetAddressResponse {
                chain: request.chain,
                address: "0x0000000000000000000000000000000000000000".into(),
                mac: None,
                public_key: None,
            })
        }

        async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
            Ok(SignTxResponse {
                chain: request.chain,
                v: 1,
                r: vec![0xAA; 32],
                s: vec![0xBB; 32],
            })
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

    struct CodeEntryController;

    #[async_trait::async_trait]
    impl PairingController for CodeEntryController {
        async fn on_prompt(
            &self,
            prompt: PairingPrompt,
        ) -> std::result::Result<PairingDecision, String> {
            if prompt.available_methods.contains(&PairingMethod::CodeEntry) {
                Ok(PairingDecision::SubmitTag {
                    method: PairingMethod::CodeEntry,
                    tag: "123456".into(),
                })
            } else {
                Err("no supported method".into())
            }
        }
    }

    struct InMemoryStorage {
        snapshot: Mutex<HostSnapshot>,
        persist_calls: Mutex<usize>,
    }

    impl InMemoryStorage {
        fn new(snapshot: HostSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(snapshot),
                persist_calls: Mutex::new(0),
            }
        }

        fn snapshot(&self) -> HostSnapshot {
            self.snapshot.lock().clone()
        }

        fn persist_calls(&self) -> usize {
            *self.persist_calls.lock()
        }
    }

    #[async_trait::async_trait]
    impl ThpStorage for InMemoryStorage {
        async fn load(&self) -> std::result::Result<HostSnapshot, StorageError> {
            Ok(self.snapshot.lock().clone())
        }

        async fn persist(&self, snapshot: &HostSnapshot) -> std::result::Result<(), StorageError> {
            *self.snapshot.lock() = snapshot.clone();
            *self.persist_calls.lock() += 1;
            Ok(())
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

    #[tokio::test]
    async fn code_entry_pairing_populates_cpace_inputs_before_tag() {
        let backend = MockBackend::code_entry_flow();
        let controller = CodeEntryController;
        let mut workflow = ThpWorkflow::new(
            backend,
            HostConfig {
                pairing_methods: vec![PairingMethod::CodeEntry],
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
            .expect("code-entry pairing succeeds");

        let (backend, _, _) = workflow.into_parts();
        let requests = backend.code_entry_challenge_requests.lock().clone();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].challenge.len(), 32);

        let tag_request = backend
            .last_tag_request
            .lock()
            .clone()
            .expect("tag request recorded");
        match tag_request {
            PairingTagRequest::CodeEntry {
                code,
                commitment,
                challenge,
                trezor_cpace_public_key,
                ..
            } => {
                assert_eq!(code, "123456");
                assert_eq!(commitment.as_ref().map(Vec::len), Some(32));
                assert_eq!(challenge.as_ref().map(Vec::len), Some(32));
                assert_eq!(trezor_cpace_public_key.as_ref().map(Vec::len), Some(32));
            }
            _ => panic!("expected code-entry tag request"),
        }
    }

    #[tokio::test]
    async fn code_entry_retry_requests_fresh_commitment() {
        let backend = MockBackend::code_entry_flow();
        backend
            .select_responses
            .lock()
            .push_back(SelectMethodResponse::CodeEntryCommitment {
                commitment: vec![0xBB; 32],
            });
        backend.tag_responses.lock().clear();
        backend.tag_responses.lock().extend([
            PairingTagResponse::Retry("firmware failure code=99: Firmware error".into()),
            PairingTagResponse::Accepted { secret: vec![9, 9] },
        ]);
        let controller = CodeEntryController;
        let mut workflow = ThpWorkflow::new(
            backend,
            HostConfig {
                pairing_methods: vec![PairingMethod::CodeEntry],
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
            .expect("code-entry pairing succeeds after retry");

        let (backend, _, _) = workflow.into_parts();
        let challenge_requests = backend.code_entry_challenge_requests.lock().clone();
        assert_eq!(
            challenge_requests.len(),
            2,
            "should request a fresh challenge after fresh commitment"
        );
        let tag_requests = backend.tag_requests.lock().clone();
        assert_eq!(tag_requests.len(), 2, "should prompt and submit code twice");
    }

    #[tokio::test]
    async fn with_storage_loads_existing_host_snapshot() {
        let backend = MockBackend::autopair();
        let initial_snapshot = HostSnapshot {
            static_key: Some(vec![0xAA; 32]),
            known_credentials: vec![KnownCredential {
                credential: "persisted-cred".into(),
                trezor_static_public_key: Some(vec![0xBB; 32]),
                autoconnect: true,
            }],
        };
        let storage = Arc::new(InMemoryStorage::new(initial_snapshot.clone()));
        let config = HostConfig {
            pairing_methods: vec![PairingMethod::SkipPairing],
            known_credentials: vec![],
            static_key: None,
            host_name: "host".into(),
            app_name: "app".into(),
        };

        let workflow = ThpWorkflow::with_storage(backend, config, storage)
            .await
            .expect("workflow with storage should initialize");

        assert_eq!(
            workflow.host_config().static_key,
            initial_snapshot.static_key
        );
        assert_eq!(workflow.host_config().known_credentials.len(), 1);
        assert_eq!(
            workflow.host_config().known_credentials[0].credential,
            initial_snapshot.known_credentials[0].credential
        );
        assert_eq!(
            workflow.host_config().known_credentials[0].trezor_static_public_key,
            initial_snapshot.known_credentials[0].trezor_static_public_key
        );
        assert_eq!(
            workflow.host_config().known_credentials[0].autoconnect,
            initial_snapshot.known_credentials[0].autoconnect
        );
    }

    #[tokio::test]
    async fn handshake_persists_host_state_to_storage() {
        let backend = MockBackend::autopair();
        let storage = Arc::new(InMemoryStorage::new(HostSnapshot::default()));
        let config = HostConfig {
            pairing_methods: vec![PairingMethod::SkipPairing],
            known_credentials: vec![],
            static_key: None,
            host_name: "host".into(),
            app_name: "app".into(),
        };

        let mut workflow = ThpWorkflow::with_storage(backend, config, storage.clone())
            .await
            .expect("workflow with storage should initialize");
        workflow.create_channel().await.expect("create channel");
        workflow.handshake(false).await.expect("handshake");

        let persisted = storage.snapshot();
        assert_eq!(persisted.static_key, Some(vec![12]));
        assert_eq!(persisted.known_credentials.len(), 1);
        assert_eq!(persisted.known_credentials[0].credential, "cred1");
        assert!(storage.persist_calls() >= 1);
    }

    #[tokio::test]
    async fn get_address_requires_paired_phase() {
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

        let err = workflow
            .get_address(GetAddressRequest::ethereum(vec![
                0x8000_002c,
                0x8000_003c,
                0x8000_0000,
                0,
                0,
            ]))
            .await
            .expect_err("should fail before pairing");
        assert!(matches!(err, ThpWorkflowError::InvalidPhase));
    }

    #[tokio::test]
    async fn sign_tx_requires_paired_phase() {
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

        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_to("0xdead".into());
        let err = workflow
            .sign_tx(request)
            .await
            .expect_err("should fail before pairing");
        assert!(matches!(err, ThpWorkflowError::InvalidPhase));
    }
}
