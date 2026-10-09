use hw_chain::Chain;

use super::ThpWorkflow;
use crate::thp::backend::{BackendError, ThpBackend};
use crate::thp::error::Result;
use crate::thp::state::Phase;
use crate::thp::types::{
    SignMessageRequest, SignMessageResponse, SignTxRequest, SignTxResponse, SignTypedDataRequest,
    SignTypedDataResponse, decode_solana_public_key,
};

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
    pub async fn sign_tx(&mut self, request: SignTxRequest) -> Result<SignTxResponse> {
        self.require_phase(Phase::Paired)?;
        Ok(self.backend.sign_tx(request).await?)
    }

    pub async fn sign_message(
        &mut self,
        mut request: SignMessageRequest,
    ) -> Result<SignMessageResponse> {
        self.require_phase(Phase::Paired)?;
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

    pub async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> Result<SignTypedDataResponse> {
        self.require_phase(Phase::Paired)?;
        Ok(self.backend.sign_typed_data(request).await?)
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
}
