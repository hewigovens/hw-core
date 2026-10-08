use super::*;
use crate::thp::Chain;
use crate::thp::backend::BackendError;
use crate::thp::error::{Result, ThpWorkflowError};
use crate::thp::state::Phase;
use crate::thp::storage::{HostSnapshot, StorageError, ThpStorage};
use crate::thp::testing::MockBackend;
use crate::thp::types::*;
use parking_lot::Mutex;
use std::sync::Arc;

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
    assert!(backend.end_called);
}

#[tokio::test]
async fn create_session_sends_nfkd_normalized_passphrase() {
    let mut workflow = ThpWorkflow::new(
        MockBackend::autopair(),
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

    workflow
        .create_session(Some("caf\u{e9} \u{fb01}".into()), false, false)
        .await
        .unwrap();
    workflow.create_session(None, false, false).await.unwrap();

    let (backend, _, _) = workflow.into_parts();
    assert_eq!(
        backend.session_passphrases,
        vec![Some("cafe\u{301} fi".to_string()), None]
    );
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
    assert!(backend.pairing_request.is_some());
    assert!(backend.end_called);
}

#[tokio::test]
async fn pairing_request_replaces_curly_single_quotes_in_names() {
    let mut workflow = ThpWorkflow::new(
        MockBackend::pairing_flow(),
        HostConfig {
            pairing_methods: vec![PairingMethod::QrCode],
            known_credentials: vec![],
            static_key: None,
            host_name: "H\u{2019}s iPhone".into(),
            app_name: "\u{2018}hw\u{2019} app's \"core\"".into(),
        },
    );

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    workflow.pairing(Some(&TestController)).await.unwrap();

    let (backend, config, _) = workflow.into_parts();
    let request = backend.pairing_request.expect("pairing request sent");
    assert_eq!(request.host_name, "H's iPhone");
    assert_eq!(request.app_name, "'hw' app's \"core\"");
    assert_eq!(config.host_name, "H\u{2019}s iPhone");
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
    assert!(backend.end_called);
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
    let requests = backend.code_entry_challenge_requests.clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].challenge.len(), 32);

    let tag_request = backend
        .tag_requests
        .last()
        .cloned()
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
    assert!(backend.pairing_request.is_some());
    assert_eq!(backend.code_entry_challenge_requests.len(), 1);
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
    let mut backend = MockBackend::code_entry_flow();
    backend
        .select_responses
        .push_back(SelectMethodResponse::CodeEntryCommitment {
            commitment: vec![0xBB; 32],
        });
    backend.tag_responses.clear();
    backend.tag_responses.extend([
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
    let challenge_requests = backend.code_entry_challenge_requests.clone();
    assert_eq!(
        challenge_requests.len(),
        2,
        "should request a fresh challenge after fresh commitment"
    );
    let tag_requests = backend.tag_requests.clone();
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
        known_credentials: vec![KnownCredential {
            credential: "other-device".into(),
            trezor_static_public_key: Some(vec![0x77; 32]),
            autoconnect: false,
        }],
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
    let static_key = persisted.static_key.expect("host static key persisted");
    assert_eq!(static_key.len(), 32);
    assert_eq!(persisted.known_credentials.len(), 1);
    assert_eq!(persisted.known_credentials[0].credential, "other-device");
    assert!(storage.persist_calls() >= 1);

    // A second handshake must reuse the persisted host key.
    let (backend, config, _) = workflow.into_parts();
    let mut workflow = ThpWorkflow::new(backend, config);
    workflow.create_channel().await.expect("create channel");
    workflow.handshake(false).await.expect("handshake");
    assert_eq!(workflow.host_config().static_key, Some(static_key));
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
async fn get_nonce_requires_paired_phase() {
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
        .get_nonce()
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

#[tokio::test]
async fn handshake_reallocates_channel_only_when_unlock_flag_differs() {
    let config = HostConfig {
        pairing_methods: vec![PairingMethod::SkipPairing],
        known_credentials: vec![],
        static_key: None,
        host_name: "host".into(),
        app_name: "app".into(),
    };

    let mut workflow = ThpWorkflow::new(MockBackend::autopair(), config.clone());
    workflow.create_channel().await.unwrap();
    workflow.handshake(true).await.unwrap();
    let (backend, _, _) = workflow.into_parts();
    assert_eq!(backend.channel_requests, vec![true]);

    let mut workflow = ThpWorkflow::new(MockBackend::autopair(), config);
    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    let (backend, _, _) = workflow.into_parts();
    assert_eq!(backend.channel_requests, vec![true, false]);
}

const SOL_PATH: [u32; 4] = [0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000];

async fn paired_workflow(backend: MockBackend) -> ThpWorkflow<MockBackend> {
    let mut workflow = ThpWorkflow::new(backend, HostConfig::new("host", "app"));
    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    workflow
}

async fn sign_solana(
    backend: MockBackend,
    signers: Vec<[u8; 32]>,
) -> (Result<SignMessageResponse>, MockBackend) {
    let mut workflow = paired_workflow(backend).await;
    let result = workflow
        .sign_message(SignMessageRequest::solana(
            SOL_PATH.to_vec(),
            "hello".into(),
            signers,
        ))
        .await;
    (result, workflow.into_parts().0)
}

#[tokio::test]
async fn solana_sign_message_uses_silently_fetched_key_as_sole_signer() {
    let mut backend = MockBackend::autopair();
    let key = bs58::encode([0x33; 32]).into_string();
    backend.public_key_response = Some(key.clone());

    let (response, backend) = sign_solana(backend, vec![]).await;

    assert_eq!(response.unwrap().address, key);
    assert_eq!(
        backend.last_get_public_key_request,
        Some((Chain::Solana, SOL_PATH.to_vec()))
    );
    assert_eq!(
        backend.last_sign_message_request.unwrap().solana_signers,
        vec![[0x33; 32]]
    );
}

#[tokio::test]
async fn solana_sign_message_sends_given_signers_without_key_fetch() {
    let lone_signer_address = bs58::encode([0x11; 32]).into_string();
    for (signers, expected_address) in [
        (vec![[0x11; 32]], lone_signer_address.as_str()),
        (vec![[0x22; 32], [0x11; 32]], ""),
    ] {
        let (response, backend) = sign_solana(MockBackend::autopair(), signers.clone()).await;

        assert_eq!(response.unwrap().address, expected_address);
        assert_eq!(backend.counters.get_public_key_calls, 0);
        assert_eq!(
            backend.last_sign_message_request.unwrap().solana_signers,
            signers
        );
    }
}

#[tokio::test]
async fn solana_sign_message_rejects_malformed_device_public_key() {
    let mut backend = MockBackend::autopair();
    backend.public_key_response = Some("7bWpTW".into());

    let (response, backend) = sign_solana(backend, vec![]).await;

    assert!(matches!(
        response,
        Err(ThpWorkflowError::Backend(BackendError::Device(_)))
    ));
    assert_eq!(backend.counters.sign_message_calls, 0);
}
