use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use tracing::debug;
use unicode_normalization::UnicodeNormalization;

use super::{
    backend::{BackendError, ThpBackend},
    crypto::Curve25519KeyPair,
    error::{Result, ThpWorkflowError},
    state::{HandshakeCache, HandshakeCredentials, Phase, ThpState},
    storage::{HostSnapshot, ThpStorage},
    types::{
        CodeEntryChallengeRequest, CreateChannelRequest, CreateSessionRequest, GetAddressRequest,
        GetAddressResponse, HandshakeCompletionState, HandshakeRequest, HostConfig,
        KnownCredential, PairingController, PairingDecision, PairingMethod, PairingPrompt,
        PairingTagRequest, SelectMethodRequest, SignMessageRequest, SignMessageResponse,
        SignTxRequest, SignTxResponse, SignTypedDataRequest, SignTypedDataResponse,
        decode_solana_public_key,
    },
};
use hw_chain::Chain;

pub struct ThpWorkflow<B> {
    backend: B,
    config: HostConfig,
    state: ThpState,
    rng: StdRng,
    storage: Option<Arc<dyn ThpStorage>>,
    channel_try_to_unlock: Option<bool>,
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
            channel_try_to_unlock: None,
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
            channel_try_to_unlock: None,
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
                ..HostSnapshot::default()
            };
            storage
                .persist(&snapshot)
                .await
                .map_err(ThpWorkflowError::Storage)?;
        }
        Ok(())
    }

    pub async fn create_channel(&mut self) -> Result<()> {
        self.open_channel(true).await
    }

    async fn open_channel(&mut self, try_to_unlock: bool) -> Result<()> {
        if self.state.phase() != Phase::Handshake {
            return Err(ThpWorkflowError::InvalidPhase);
        }

        let response = self
            .backend
            .create_channel(CreateChannelRequest { try_to_unlock })
            .await?;

        let host_supported: Vec<PairingMethod> = if self.config.pairing_methods.is_empty() {
            response.properties.pairing_methods
        } else {
            response
                .properties
                .pairing_methods
                .into_iter()
                .filter(|m| self.config.pairing_methods.contains(m))
                .collect()
        };

        if host_supported.is_empty() {
            return Err(ThpWorkflowError::NoCommonPairingMethod);
        }

        self.state.set_handshake_cache(HandshakeCache {
            channel: response.channel,
            pairing_methods: host_supported,
        });
        self.channel_try_to_unlock = Some(try_to_unlock);
        Ok(())
    }

    pub async fn handshake(&mut self, try_to_unlock: bool) -> Result<()> {
        if self.state.handshake_cache().is_none() {
            return Err(ThpWorkflowError::MissingHandshake);
        }
        // try_to_unlock is fixed when the channel is allocated.
        if self.channel_try_to_unlock != Some(try_to_unlock) {
            self.open_channel(try_to_unlock).await?;
        }
        let pairing_methods = self
            .state
            .handshake_cache()
            .map(|cache| cache.pairing_methods.clone())
            .ok_or(ThpWorkflowError::MissingHandshake)?;

        let static_key = self.host_static_key();
        let response = self
            .backend
            .handshake(HandshakeRequest {
                static_key,
                known_credentials: self.config.known_credentials.clone(),
            })
            .await?;
        self.channel_try_to_unlock = None;

        let selected_credential = response.selected_credential;
        let pairing_credentials: Vec<KnownCredential> =
            selected_credential.iter().cloned().collect();

        if let Some(method) = pairing_methods.first().copied() {
            self.state.set_pairing_method(method);
        }
        self.state.set_handshake_credentials(HandshakeCredentials {
            pairing_methods,
            handshake_hash: response.handshake_hash,
            host_static_public_key: Curve25519KeyPair::from_private_key(static_key)
                .public_key
                .to_vec(),
            pairing_credentials,
            ..HandshakeCredentials::default()
        });

        match response.state {
            HandshakeCompletionState::RequiresPairing => {
                if let Some(selected) = selected_credential {
                    self.config
                        .known_credentials
                        .retain(|c| c.credential != selected.credential);
                }
                self.state.set_is_paired(false);
                self.state.set_phase(Phase::Pairing);
            }
            HandshakeCompletionState::Paired => {
                // Mirror Suite: paired handshake completion still needs finalization.
                self.state.set_is_paired(true);
                self.state.set_phase(Phase::Pairing);
            }
            HandshakeCompletionState::AutoPaired => {
                self.state.set_is_paired(true);
                self.state.set_phase(Phase::Paired);
                self.backend.end_request().await?;
            }
        }

        self.persist_host_state().await?;
        Ok(())
    }

    fn host_static_key(&mut self) -> [u8; 32] {
        if let Some(key) = self
            .config
            .static_key
            .as_deref()
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
        {
            return key;
        }
        let mut key = [0u8; 32];
        self.rng.fill(&mut key);
        self.config.static_key = Some(key.to_vec());
        key
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
            .cloned()
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

        self.backend
            .pairing_request(super::types::PairingRequest {
                host_name: sanitize_pairing_name(&self.config.host_name),
                app_name: sanitize_pairing_name(&self.config.app_name),
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
                    // Firmware already exited pairing context; no end_request needed.
                    self.state.set_is_paired(true);
                    self.state.set_phase(Phase::Paired);
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
                        let Some(controller) = controller else {
                            return Err(ThpWorkflowError::PairingInteractionRequired);
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
                    let Some(controller) = controller else {
                        return Err(ThpWorkflowError::PairingInteractionRequired);
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

        self.finalize_pairing_with_credential_request(&handshake)
            .await
    }

    pub async fn submit_code_entry_pairing_tag(&mut self, code: String) -> Result<()> {
        if self.state.phase() != Phase::Pairing {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        if self.state.is_paired() {
            return Err(ThpWorkflowError::AlreadyPaired);
        }

        let handshake = self
            .state
            .handshake_credentials()
            .cloned()
            .ok_or(ThpWorkflowError::MissingHandshakeCredentials)?;

        if self.state.pairing_method() != Some(PairingMethod::CodeEntry) {
            return Err(ThpWorkflowError::PairingInteractionRequired);
        }
        if handshake.handshake_commitment.is_none()
            || handshake.code_entry_challenge.is_none()
            || handshake.trezor_cpace_public_key.is_none()
        {
            return Err(ThpWorkflowError::PairingInteractionRequired);
        }

        let request = PairingTagRequest::CodeEntry {
            code,
            handshake_hash: handshake.handshake_hash.clone(),
            commitment: handshake.handshake_commitment.clone(),
            challenge: handshake.code_entry_challenge.clone(),
            trezor_cpace_public_key: handshake.trezor_cpace_public_key.clone(),
        };

        match self.backend.send_pairing_tag(request).await? {
            super::types::PairingTagResponse::Accepted { .. } => {}
            super::types::PairingTagResponse::Retry(reason) => {
                return Err(ThpWorkflowError::Backend(
                    super::backend::BackendError::Device(reason),
                ));
            }
        }

        self.finalize_pairing_with_credential_request(&handshake)
            .await
    }

    async fn finalize_pairing_with_credential_request(
        &mut self,
        handshake: &HandshakeCredentials,
    ) -> Result<()> {
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
                passphrase: passphrase.map(|p| p.nfkd().collect()),
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

    pub async fn get_nonce(&mut self) -> Result<Vec<u8>> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        self.backend.get_nonce().await.map_err(Into::into)
    }

    pub async fn sign_tx(&mut self, request: SignTxRequest) -> Result<SignTxResponse> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        self.backend.sign_tx(request).await.map_err(Into::into)
    }

    pub async fn sign_message(
        &mut self,
        mut request: SignMessageRequest,
    ) -> Result<SignMessageResponse> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        let signer_address = match request.chain {
            Chain::Solana => self.resolve_solana_signers(&mut request).await?,
            Chain::Ethereum | Chain::Bitcoin => None,
        };
        let mut response = self.backend.sign_message(request).await?;
        if let Some(address) = signer_address {
            response.address = address;
        }
        Ok(response)
    }

    /// Mirrors Suite: without signers, the silently fetched signing key is the sole signer.
    async fn resolve_solana_signers(
        &mut self,
        request: &mut SignMessageRequest,
    ) -> Result<Option<String>> {
        match request.solana_signers.as_slice() {
            [] => {}
            // Firmware rejects a signing key outside the signer set, so a lone signer is the signer.
            [signer] => return Ok(Some(bs58::encode(signer).into_string())),
            _ => return Ok(None),
        }
        let public_key = self
            .backend
            .get_public_key(Chain::Solana, request.path.clone())
            .await?;
        let signer = decode_solana_public_key(&public_key)
            .ok_or_else(|| BackendError::Device("invalid Solana public key".into()))?;
        request.solana_signers.push(signer);
        Ok(Some(public_key))
    }

    pub async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResponse> {
        if self.state.phase() != Phase::Paired {
            return Err(ThpWorkflowError::InvalidPhase);
        }
        self.backend
            .sign_typed_data(request)
            .await
            .map_err(Into::into)
    }

    pub async fn abort(&mut self) -> Result<()> {
        self.backend.abort().await?;
        self.state.reset();
        Ok(())
    }
}

// Matches Suite (af8e018fa): the device font cannot render typographic single quotes.
fn sanitize_pairing_name(name: &str) -> String {
    name.replace(['\u{2018}', '\u{2019}'], "'")
}

#[cfg(test)]
mod tests;
