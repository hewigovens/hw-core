use unicode_normalization::UnicodeNormalization;

use super::ThpWorkflow;
use crate::thp::backend::ThpBackend;
use crate::thp::error::Result;
use crate::thp::state::Phase;
use crate::thp::types::{CreateSessionRequest, GetAddressRequest, GetAddressResponse};

impl<B> ThpWorkflow<B>
where
    B: ThpBackend + Send,
{
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
        self.require_phase(Phase::Paired)?;
        Ok(self.backend.get_address(request).await?)
    }

    pub async fn get_nonce(&mut self) -> Result<Vec<u8>> {
        self.require_phase(Phase::Paired)?;
        Ok(self.backend.get_nonce().await?)
    }
}
