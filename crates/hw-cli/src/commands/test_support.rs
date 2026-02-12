use std::collections::VecDeque;

use trezor_connect::thp::types::{
    CodeEntryChallengeRequest, CodeEntryChallengeResponse, CreateChannelRequest,
    CreateChannelResponse, CreateSessionRequest, CreateSessionResponse, CredentialRequest,
    CredentialResponse, GetAddressRequest, GetAddressResponse, HandshakeCompletionRequest,
    HandshakeCompletionResponse, HandshakeCompletionState, HandshakeInitOutcome,
    HandshakeInitRequest, KnownCredential, PairingRequest, PairingRequestApproved,
    PairingTagRequest, PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
    SignTxRequest, SignTxResponse, ThpProperties,
};
use trezor_connect::thp::{
    Chain, HostConfig, PairingMethod,
    backend::{BackendError, BackendResult, ThpBackend},
};

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct MockCounters {
    pub credential_calls: usize,
    pub create_session_calls: usize,
    pub get_address_calls: usize,
    pub sign_tx_calls: usize,
}

pub struct MockBackend {
    pub counters: MockCounters,
    pub last_get_address_request: Option<GetAddressRequest>,
    pub last_sign_tx_request: Option<SignTxRequest>,
    pub create_session_responses: VecDeque<BackendResult<CreateSessionResponse>>,
    pub get_address_response: Option<GetAddressResponse>,
    pub sign_tx_response: Option<SignTxResponse>,
    handshake_hash: Vec<u8>,
    handshake_completion_state: HandshakeCompletionState,
    selected_credential: Option<KnownCredential>,
}

impl MockBackend {
    pub fn paired_with_session_retry(handshake_hash: &[u8]) -> Self {
        Self {
            counters: MockCounters::default(),
            last_get_address_request: None,
            last_sign_tx_request: None,
            create_session_responses: VecDeque::from([
                Err(BackendError::Device("device returned error code 99".into())),
                Ok(CreateSessionResponse),
            ]),
            get_address_response: None,
            sign_tx_response: None,
            handshake_hash: handshake_hash.to_vec(),
            handshake_completion_state: HandshakeCompletionState::Paired,
            selected_credential: Some(KnownCredential {
                credential: "cred".into(),
                trezor_static_public_key: Some(vec![0x55; 32]),
                autoconnect: false,
            }),
        }
    }

    pub fn autopaired(handshake_hash: &[u8]) -> Self {
        Self {
            counters: MockCounters::default(),
            last_get_address_request: None,
            last_sign_tx_request: None,
            create_session_responses: VecDeque::from([Ok(CreateSessionResponse)]),
            get_address_response: None,
            sign_tx_response: None,
            handshake_hash: handshake_hash.to_vec(),
            handshake_completion_state: HandshakeCompletionState::AutoPaired,
            selected_credential: None,
        }
    }

    pub fn with_get_address_response(mut self, response: GetAddressResponse) -> Self {
        self.get_address_response = Some(response);
        self
    }

    pub fn with_sign_tx_response(mut self, response: SignTxResponse) -> Self {
        self.sign_tx_response = Some(response);
        self
    }

    fn handshake_outcome(&self) -> HandshakeInitOutcome {
        HandshakeInitOutcome {
            host_encrypted_static_pubkey: vec![1, 2, 3],
            encrypted_payload: vec![4, 5, 6],
            trezor_encrypted_static_pubkey: vec![7, 8, 9],
            handshake_hash: self.handshake_hash.clone(),
            host_key: vec![0x11; 32],
            trezor_key: vec![0x22; 32],
            host_static_key: vec![0x33; 32],
            host_static_public_key: vec![0x44; 32],
            pairing_methods: vec![PairingMethod::CodeEntry],
            credentials: self.selected_credential.clone().into_iter().collect(),
            selected_credential: self.selected_credential.clone(),
            nfc_data: None,
            handshake_commitment: None,
            trezor_cpace_public_key: None,
            code_entry_challenge: None,
        }
    }
}

impl ThpBackend for MockBackend {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        Ok(CreateChannelResponse {
            nonce: request.nonce,
            channel: 0xBEEF,
            handshake_hash: self.handshake_hash.clone(),
            properties: ThpProperties {
                internal_model: "T3W1".into(),
                model_variant: 1,
                protocol_version_major: 2,
                protocol_version_minor: 0,
                pairing_methods: vec![PairingMethod::CodeEntry],
            },
        })
    }

    async fn handshake_init(
        &mut self,
        _request: HandshakeInitRequest,
    ) -> BackendResult<HandshakeInitOutcome> {
        Ok(self.handshake_outcome())
    }

    async fn handshake_complete(
        &mut self,
        _request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse> {
        Ok(HandshakeCompletionResponse {
            state: self.handshake_completion_state,
        })
    }

    async fn pairing_request(
        &mut self,
        _request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        Err(BackendError::Transport("unexpected pairing_request".into()))
    }

    async fn select_pairing_method(
        &mut self,
        _request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        Err(BackendError::Transport(
            "unexpected select_pairing_method".into(),
        ))
    }

    async fn code_entry_challenge(
        &mut self,
        _request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        Err(BackendError::Transport(
            "unexpected code_entry_challenge".into(),
        ))
    }

    async fn send_pairing_tag(
        &mut self,
        _request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        Err(BackendError::Transport(
            "unexpected send_pairing_tag".into(),
        ))
    }

    async fn credential_request(
        &mut self,
        _request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        self.counters.credential_calls += 1;
        if self.selected_credential.is_none() {
            return Err(BackendError::Transport(
                "unexpected credential_request".into(),
            ));
        }

        Ok(CredentialResponse {
            trezor_static_public_key: vec![0x66; 32],
            credential: "cred".into(),
            autoconnect: false,
        })
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        Ok(())
    }

    async fn create_new_session(
        &mut self,
        _request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        self.counters.create_session_calls += 1;
        self.create_session_responses
            .pop_front()
            .unwrap_or(Ok(CreateSessionResponse))
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        self.counters.get_address_calls += 1;
        self.last_get_address_request = Some(request.clone());
        self.get_address_response.clone().ok_or_else(|| {
            BackendError::Transport("unexpected get_address without canned response".into())
        })
    }

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
        self.counters.sign_tx_calls += 1;
        self.last_sign_tx_request = Some(request);
        self.sign_tx_response.clone().ok_or_else(|| {
            BackendError::Transport("unexpected sign_tx without canned response".into())
        })
    }

    async fn abort(&mut self) -> BackendResult<()> {
        Ok(())
    }
}

pub fn canned_eth_address_response(address: &str) -> GetAddressResponse {
    GetAddressResponse {
        chain: Chain::Ethereum,
        address: address.to_owned(),
        mac: Some(vec![0xAA; 32]),
        public_key: Some("xpub-test".to_string()),
    }
}

pub fn canned_eth_sign_response() -> SignTxResponse {
    SignTxResponse {
        chain: Chain::Ethereum,
        v: 0,
        r: vec![0xAA; 32],
        s: vec![0xBB; 32],
    }
}

pub fn default_test_host_config() -> HostConfig {
    let mut config = HostConfig::new("test-host", "hw-core/cli");
    config.pairing_methods = vec![PairingMethod::CodeEntry];
    config
}
