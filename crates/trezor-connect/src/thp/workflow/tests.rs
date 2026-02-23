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
    require_end_before_session: bool,
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
            require_end_before_session: false,
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

    fn paired_connection_flow() -> Self {
        Self {
            create_channel_resp: CreateChannelResponse {
                nonce: [4u8; 8],
                channel: 4,
                handshake_hash: b"paired".to_vec(),
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
                handshake_hash: b"paired".to_vec(),
                host_key: vec![10],
                trezor_key: vec![11],
                host_static_key: vec![12],
                host_static_public_key: vec![13],
                pairing_methods: vec![PairingMethod::CodeEntry],
                credentials: vec![KnownCredential {
                    credential: "paired-cred".into(),
                    trezor_static_public_key: Some(vec![0x55; 32]),
                    autoconnect: false,
                }],
                selected_credential: Some(KnownCredential {
                    credential: "paired-cred".into(),
                    trezor_static_public_key: Some(vec![0x55; 32]),
                    autoconnect: false,
                }),
                nfc_data: None,
                handshake_commitment: None,
                trezor_cpace_public_key: None,
                code_entry_challenge: None,
            },
            handshake_state: HandshakeCompletionState::Paired,
            credential_response: Some(CredentialResponse {
                trezor_static_public_key: vec![0x56; 32],
                credential: "refreshed-cred".into(),
                autoconnect: false,
            }),
            require_end_before_session: true,
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
            require_end_before_session: false,
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
            require_end_before_session: false,
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
        if self.require_end_before_session && !*self.end_called.lock() {
            return Err(BackendError::SessionConfirmationRequired);
        }
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

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        Ok(SignMessageResponse {
            chain: request.chain,
            address: "0x0000000000000000000000000000000000000000".into(),
            signature: vec![0xAB; 65],
        })
    }

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        Ok(SignTypedDataResponse {
            chain: request.chain,
            address: "0x0000000000000000000000000000000000000000".into(),
            signature: vec![0xCD; 65],
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
async fn paired_handshake_requires_connection_confirmation_flow() {
    let backend = MockBackend::paired_connection_flow();
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

    assert!(workflow.state().is_paired());
    assert_eq!(workflow.state().phase(), Phase::Pairing);

    let err = workflow
        .create_session(None, false, false)
        .await
        .expect_err("session must fail before connection confirmation");
    assert!(matches!(
        err,
        ThpWorkflowError::Backend(BackendError::SessionConfirmationRequired)
    ));

    workflow
        .pairing(None)
        .await
        .expect("connection flow succeeds");
    assert_eq!(workflow.state().phase(), Phase::Paired);
    workflow
        .create_session(None, false, false)
        .await
        .expect("session succeeds after connection confirmation");

    let (backend, _, state) = workflow.into_parts();
    assert!(state.is_paired());
    assert_eq!(state.phase(), Phase::Paired);
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
async fn code_entry_pairing_without_controller_primes_device_prompt() {
    let backend = MockBackend::code_entry_flow();
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
    let err = workflow
        .pairing(None)
        .await
        .expect_err("pairing should pause for host interaction");
    assert!(matches!(err, ThpWorkflowError::PairingInteractionRequired));

    let creds = workflow
        .state()
        .handshake_credentials()
        .expect("handshake creds available");
    assert!(creds.handshake_commitment.is_some());
    assert!(creds.code_entry_challenge.is_some());
    assert!(creds.trezor_cpace_public_key.is_some());

    let (backend, _, _) = workflow.into_parts();
    assert!(*backend.pairing_requested.lock());
    assert_eq!(backend.code_entry_challenge_requests.lock().len(), 1);
}

#[tokio::test]
async fn code_entry_submit_tag_completes_after_pairing_start() {
    let backend = MockBackend::code_entry_flow();
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
        .pairing(None)
        .await
        .expect_err("pairing should pause for host interaction");
    workflow
        .submit_code_entry_pairing_tag("123456".into())
        .await
        .expect("submit code completes pairing");

    assert!(workflow.state().is_paired());
    assert_eq!(workflow.state().phase(), Phase::Paired);
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
        ..HostSnapshot::default()
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
