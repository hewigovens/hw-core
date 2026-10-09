use super::ThpWorkflow;
use crate::thp::backend::ThpBackend;
use crate::thp::crypto::Curve25519KeyPair;
use crate::thp::error::{Result, ThpWorkflowError};
use crate::thp::state::{HandshakeCache, HandshakeCredentials, Phase};
use crate::thp::types::{
    CreateChannelRequest, HandshakeCompletionState, HandshakeRequest, PairingMethod,
};

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub async fn create_channel(&mut self) -> Result<()> {
        self.open_channel(true).await
    }

    async fn open_channel(&mut self, try_to_unlock: bool) -> Result<()> {
        self.require_phase(Phase::Handshake)?;

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

        let static_key = self.config.static_key_or_generate(&mut self.rng);
        let response = self
            .backend
            .handshake(HandshakeRequest {
                static_key,
                known_credentials: self.config.known_credentials.clone(),
            })
            .await?;
        self.channel_try_to_unlock = None;

        let selected_credential = response.selected_credential;
        if let Some(method) = pairing_methods.first().copied() {
            self.state.set_pairing_method(method);
        }
        self.state.set_handshake_credentials(HandshakeCredentials {
            pairing_methods,
            handshake_hash: response.handshake_hash,
            host_static_public_key: Curve25519KeyPair::from_private_key(static_key)
                .public_key
                .to_vec(),
            pairing_credentials: selected_credential.iter().cloned().collect(),
            ..HandshakeCredentials::default()
        });

        match response.state {
            HandshakeCompletionState::RequiresPairing => {
                if let Some(selected) = selected_credential {
                    self.config.forget_credential(&selected.credential);
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
}
