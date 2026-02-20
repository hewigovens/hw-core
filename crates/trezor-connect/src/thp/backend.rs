use thiserror::Error;

use super::types::*;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("device error: {0}")]
    Device(String),
    #[error("unsupported pairing method")]
    UnsupportedPairingMethod,
}

pub type BackendResult<T> = std::result::Result<T, BackendError>;

#[allow(async_fn_in_trait)]
pub trait ThpBackend: Send {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse>;

    async fn handshake_init(
        &mut self,
        request: HandshakeInitRequest,
    ) -> BackendResult<HandshakeInitOutcome>;

    async fn handshake_complete(
        &mut self,
        request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse>;

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved>;

    async fn select_pairing_method(
        &mut self,
        request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse>;

    async fn code_entry_challenge(
        &mut self,
        request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse>;

    async fn send_pairing_tag(
        &mut self,
        request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse>;

    async fn credential_request(
        &mut self,
        request: CredentialRequest,
    ) -> BackendResult<CredentialResponse>;

    async fn end_request(&mut self) -> BackendResult<()>;

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse>;

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse>;

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse>;

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse>;

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse>;

    async fn abort(&mut self) -> BackendResult<()>;
}
