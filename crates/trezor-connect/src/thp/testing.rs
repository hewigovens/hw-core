//! Configurable in-memory `ThpBackend` for workflow tests.

use std::collections::VecDeque;

use super::Chain;
use super::backend::{BackendError, BackendResult, ThpBackend};
use super::types::{
    CodeEntryChallengeRequest, CodeEntryChallengeResponse, CreateChannelRequest,
    CreateChannelResponse, CreateSessionRequest, CreateSessionResponse, CredentialRequest,
    CredentialResponse, EthTxSignature, GetAddressRequest, GetAddressResponse,
    HandshakeCompletionState, HandshakeRequest, HandshakeResponse, KnownCredential, PairingMethod,
    PairingRequest, PairingRequestApproved, PairingTagRequest, PairingTagResponse,
    SelectMethodRequest, SelectMethodResponse, SignMessageRequest, SignMessageResponse,
    SignTxRequest, SignTxResponse, SignTypedDataRequest, SignTypedDataResponse, ThpProperties,
};

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct MockCounters {
    pub credential_calls: usize,
    pub create_session_calls: usize,
    pub get_address_calls: usize,
    pub get_public_key_calls: usize,
    pub get_nonce_calls: usize,
    pub sign_message_calls: usize,
    pub sign_typed_data_calls: usize,
    pub sign_tx_calls: usize,
}

pub struct MockBackend {
    pub create_channel_response: CreateChannelResponse,
    pub handshake_state: HandshakeCompletionState,
    pub handshake_hash: Vec<u8>,
    pub selected_credential: Option<KnownCredential>,
    pub credential_response: Option<CredentialResponse>,
    pub require_end_before_session: bool,
    pub select_responses: VecDeque<SelectMethodResponse>,
    pub code_entry_challenge_response: Option<CodeEntryChallengeResponse>,
    pub tag_responses: VecDeque<PairingTagResponse>,
    pub session_responses: VecDeque<BackendResult<CreateSessionResponse>>,

    pub counters: MockCounters,
    pub channel_requests: Vec<bool>,
    pub pairing_request: Option<PairingRequest>,
    pub end_called: bool,
    pub code_entry_challenge_requests: Vec<CodeEntryChallengeRequest>,
    pub tag_requests: Vec<PairingTagRequest>,
    pub session_passphrases: Vec<Option<String>>,
    pub last_get_address_request: Option<GetAddressRequest>,
    pub last_get_public_key_request: Option<(Chain, Vec<u32>)>,
    /// Overrides the canned address returned as the public key by `get_public_key`.
    pub public_key_response: Option<String>,
    pub last_sign_message_request: Option<SignMessageRequest>,
    pub last_sign_typed_data_request: Option<SignTypedDataRequest>,
    pub last_sign_tx_request: Option<SignTxRequest>,
}

impl MockBackend {
    fn new(
        channel: u16,
        pairing_method: PairingMethod,
        handshake_state: HandshakeCompletionState,
        handshake_hash: &[u8],
    ) -> Self {
        Self {
            create_channel_response: CreateChannelResponse {
                channel,
                properties: ThpProperties {
                    internal_model: "T3W1".into(),
                    model_variant: 1,
                    protocol_version_major: 2,
                    protocol_version_minor: 0,
                    pairing_methods: vec![pairing_method],
                },
            },
            handshake_state,
            handshake_hash: handshake_hash.to_vec(),
            selected_credential: None,
            credential_response: None,
            require_end_before_session: false,
            select_responses: VecDeque::new(),
            code_entry_challenge_response: None,
            tag_responses: VecDeque::new(),
            session_responses: VecDeque::new(),
            counters: MockCounters::default(),
            channel_requests: Vec::new(),
            pairing_request: None,
            end_called: false,
            code_entry_challenge_requests: Vec::new(),
            tag_requests: Vec::new(),
            session_passphrases: Vec::new(),
            last_get_address_request: None,
            last_get_public_key_request: None,
            public_key_response: None,
            last_sign_message_request: None,
            last_sign_typed_data_request: None,
            last_sign_tx_request: None,
        }
    }

    /// Device already paired with autoconnect; handshake lands in `Paired`.
    pub fn autopair() -> Self {
        Self {
            selected_credential: Some(KnownCredential {
                credential: "cred1".into(),
                trezor_static_public_key: Some(vec![0x11; 32]),
                autoconnect: true,
            }),
            credential_response: Some(CredentialResponse {
                trezor_static_public_key: vec![0x11; 32],
                credential: "cred1".into(),
                autoconnect: true,
            }),
            ..Self::new(
                1,
                PairingMethod::SkipPairing,
                HandshakeCompletionState::AutoPaired,
                b"hash",
            )
        }
    }

    /// Known credential without autoconnect; sessions fail until the connection is confirmed.
    pub fn paired_connection_flow() -> Self {
        Self {
            selected_credential: Some(KnownCredential {
                credential: "paired-cred".into(),
                trezor_static_public_key: Some(vec![0x55; 32]),
                autoconnect: false,
            }),
            credential_response: Some(CredentialResponse {
                trezor_static_public_key: vec![0x56; 32],
                credential: "refreshed-cred".into(),
                autoconnect: false,
            }),
            require_end_before_session: true,
            ..Self::new(
                4,
                PairingMethod::CodeEntry,
                HandshakeCompletionState::Paired,
                b"paired",
            )
        }
    }

    pub fn pairing_flow() -> Self {
        Self {
            credential_response: Some(CredentialResponse {
                trezor_static_public_key: vec![0x22; 32],
                credential: "new-cred".into(),
                autoconnect: false,
            }),
            select_responses: VecDeque::from([SelectMethodResponse::PairingPreparationsFinished {
                nfc_data: None,
            }]),
            tag_responses: VecDeque::from([PairingTagResponse::Accepted { secret: vec![1, 2] }]),
            ..Self::new(
                2,
                PairingMethod::QrCode,
                HandshakeCompletionState::RequiresPairing,
                b"pair",
            )
        }
    }

    pub fn code_entry_flow() -> Self {
        Self {
            credential_response: Some(CredentialResponse {
                trezor_static_public_key: vec![0x33; 32],
                credential: "code-entry-cred".into(),
                autoconnect: false,
            }),
            select_responses: VecDeque::from([SelectMethodResponse::CodeEntryCommitment {
                commitment: vec![0xAA; 32],
            }]),
            code_entry_challenge_response: Some(CodeEntryChallengeResponse {
                trezor_cpace_public_key: vec![0x44; 32],
            }),
            tag_responses: VecDeque::from([PairingTagResponse::Accepted { secret: vec![9, 9] }]),
            ..Self::new(
                3,
                PairingMethod::CodeEntry,
                HandshakeCompletionState::RequiresPairing,
                b"code-entry",
            )
        }
    }

    /// Fails the first session attempt with a transient firmware error.
    pub fn with_transient_session_failure(mut self) -> Self {
        self.session_responses = VecDeque::from([
            Err(BackendError::DeviceFirmwareError),
            Ok(CreateSessionResponse),
        ]);
        self
    }
}

fn canned_address(chain: Chain) -> &'static str {
    match chain {
        Chain::Ethereum => "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE",
        Chain::Bitcoin => "bc1qexample000000000000000000000000000000",
        Chain::Solana => "So11111111111111111111111111111111111111112",
    }
}

impl ThpBackend for MockBackend {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        self.channel_requests.push(request.try_to_unlock);
        Ok(self.create_channel_response.clone())
    }

    async fn handshake(&mut self, _request: HandshakeRequest) -> BackendResult<HandshakeResponse> {
        Ok(HandshakeResponse {
            state: self.handshake_state,
            handshake_hash: self.handshake_hash.clone(),
            selected_credential: self.selected_credential.clone(),
        })
    }

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        self.pairing_request = Some(request);
        Ok(PairingRequestApproved)
    }

    async fn select_pairing_method(
        &mut self,
        _request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        self.select_responses
            .pop_front()
            .ok_or_else(|| BackendError::Device("no more select responses".into()))
    }

    async fn code_entry_challenge(
        &mut self,
        request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        self.code_entry_challenge_requests.push(request);
        self.code_entry_challenge_response
            .clone()
            .ok_or_else(|| BackendError::Device("unexpected code entry challenge".into()))
    }

    async fn send_pairing_tag(
        &mut self,
        request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        self.tag_requests.push(request);
        self.tag_responses
            .pop_front()
            .ok_or_else(|| BackendError::Device("unexpected tag".into()))
    }

    async fn credential_request(
        &mut self,
        _request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        self.counters.credential_calls += 1;
        self.credential_response
            .clone()
            .ok_or_else(|| BackendError::Device("no credential response".into()))
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        self.end_called = true;
        Ok(())
    }

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        self.counters.create_session_calls += 1;
        self.session_passphrases.push(request.passphrase);
        if self.require_end_before_session && !self.end_called {
            return Err(BackendError::SessionConfirmationRequired);
        }
        self.session_responses
            .pop_front()
            .unwrap_or(Ok(CreateSessionResponse))
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        self.counters.get_address_calls += 1;
        let chain = request.chain;
        self.last_get_address_request = Some(request);
        Ok(GetAddressResponse {
            chain,
            address: canned_address(chain).into(),
            mac: Some(vec![0xAA; 32]),
            public_key: Some("xpub-test".into()),
        })
    }

    async fn get_public_key(&mut self, chain: Chain, path: Vec<u32>) -> BackendResult<String> {
        self.counters.get_public_key_calls += 1;
        self.last_get_public_key_request = Some((chain, path));
        Ok(self
            .public_key_response
            .clone()
            .unwrap_or_else(|| canned_address(chain).into()))
    }

    async fn get_nonce(&mut self) -> BackendResult<Vec<u8>> {
        self.counters.get_nonce_calls += 1;
        Ok(vec![0xAA; 32])
    }

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        self.counters.sign_message_calls += 1;
        let chain = request.chain;
        self.last_sign_message_request = Some(request);
        // Mirrors the real decoders: Solana returns signed data but no address.
        let (address, signed_data) = match chain {
            Chain::Ethereum | Chain::Bitcoin => (canned_address(chain).into(), None),
            Chain::Solana => (String::new(), Some(vec![0xff; 4])),
        };
        Ok(SignMessageResponse {
            chain,
            address,
            signature: vec![0x99; 65],
            signed_data,
        })
    }

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        self.counters.sign_typed_data_calls += 1;
        let chain = request.chain;
        self.last_sign_typed_data_request = Some(request);
        Ok(SignTypedDataResponse {
            chain,
            address: canned_address(chain).into(),
            signature: vec![0x77; 65],
        })
    }

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
        self.counters.sign_tx_calls += 1;
        let chain = request.chain();
        self.last_sign_tx_request = Some(request);
        let response = match chain {
            Chain::Ethereum => SignTxResponse::Ethereum(EthTxSignature {
                v: 0,
                r: vec![0xAA; 32],
                s: vec![0xBB; 32],
            }),
            Chain::Solana => SignTxResponse::Solana {
                signature: vec![0xCC; 64],
            },
            Chain::Bitcoin => SignTxResponse::Bitcoin {
                signatures: vec![vec![0xDD; 64]],
                last_signature: vec![0xDD; 64],
            },
        };
        Ok(response)
    }

    async fn abort(&mut self) -> BackendResult<()> {
        Ok(())
    }
}
