use std::collections::VecDeque;

use super::{
    get_address_for_workflow, map_get_address_request, map_sign_message_request,
    map_sign_tx_request, map_sign_typed_data_request, pairing_confirm_connection_for_workflow,
    pairing_start_for_state, pairing_submit_code_for_workflow, sign_message_for_workflow,
    sign_tx_for_workflow, sign_typed_data_for_workflow,
};
use trezor_connect::thp::backend::{BackendError, BackendResult, ThpBackend};
use trezor_connect::thp::types::{
    CodeEntryChallengeRequest, CodeEntryChallengeResponse, CreateChannelRequest,
    CreateChannelResponse, CreateSessionRequest, CreateSessionResponse, CredentialRequest,
    CredentialResponse, GetAddressResponse, HandshakeCompletionRequest,
    HandshakeCompletionResponse, HandshakeCompletionState, HandshakeInitOutcome,
    HandshakeInitRequest, KnownCredential, PairingRequest, PairingRequestApproved,
    PairingTagRequest, PairingTagResponse, SelectMethodRequest, SelectMethodResponse,
    SignMessageRequest as BackendSignMessageRequest, SignMessageResponse,
    SignTxRequest as BackendSignTxRequest, SignTxResponse,
    SignTypedDataRequest as BackendSignTypedDataRequest, SignTypedDataResponse, ThpProperties,
};
use trezor_connect::thp::{Chain, HostConfig, PairingMethod, Phase, ThpWorkflow};

use crate::errors::HWCoreError;
use crate::types::{
    GetAddressRequest, SignMessageRequest, SignTxRequest, SignTypedDataRequest, SignatureEncoding,
};

const BTC_SIGN_WITH_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_sign_with_ref_txs.json");

struct MockBackend {
    handshake_hash: Vec<u8>,
    completion_state: HandshakeCompletionState,
    confirmed_connection: bool,
    expected_code: Option<String>,
    select_responses: VecDeque<SelectMethodResponse>,
    last_get_address_request: Option<trezor_connect::thp::GetAddressRequest>,
    last_sign_message_request: Option<BackendSignMessageRequest>,
    last_sign_tx_request: Option<BackendSignTxRequest>,
    last_sign_typed_data_request: Option<BackendSignTypedDataRequest>,
}

impl MockBackend {
    fn paired_requires_confirmation() -> Self {
        Self {
            handshake_hash: b"paired-handshake".to_vec(),
            completion_state: HandshakeCompletionState::Paired,
            confirmed_connection: false,
            expected_code: None,
            select_responses: VecDeque::new(),
            last_get_address_request: None,
            last_sign_message_request: None,
            last_sign_tx_request: None,
            last_sign_typed_data_request: None,
        }
    }

    fn requires_code_entry_pairing() -> Self {
        let mut select_responses = VecDeque::new();
        select_responses.push_back(SelectMethodResponse::CodeEntryCommitment {
            commitment: vec![0xAB; 32],
        });
        Self {
            handshake_hash: b"code-entry-handshake".to_vec(),
            completion_state: HandshakeCompletionState::RequiresPairing,
            confirmed_connection: false,
            expected_code: Some("123456".to_string()),
            select_responses,
            last_get_address_request: None,
            last_sign_message_request: None,
            last_sign_tx_request: None,
            last_sign_typed_data_request: None,
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
        Ok(HandshakeInitOutcome {
            host_encrypted_static_pubkey: vec![1, 2, 3],
            encrypted_payload: vec![4, 5, 6],
            trezor_encrypted_static_pubkey: vec![7, 8, 9],
            handshake_hash: self.handshake_hash.clone(),
            host_key: vec![0x11; 32],
            trezor_key: vec![0x22; 32],
            host_static_key: vec![0x33; 32],
            host_static_public_key: vec![0x44; 32],
            pairing_methods: vec![PairingMethod::CodeEntry],
            credentials: vec![KnownCredential {
                credential: "cred".into(),
                trezor_static_public_key: Some(vec![0x55; 32]),
                autoconnect: false,
            }],
            selected_credential: Some(KnownCredential {
                credential: "cred".into(),
                trezor_static_public_key: Some(vec![0x55; 32]),
                autoconnect: false,
            }),
            nfc_data: None,
            handshake_commitment: None,
            trezor_cpace_public_key: None,
            code_entry_challenge: None,
        })
    }

    async fn handshake_complete(
        &mut self,
        _request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse> {
        Ok(HandshakeCompletionResponse {
            state: self.completion_state,
        })
    }

    async fn pairing_request(
        &mut self,
        _request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        Ok(PairingRequestApproved)
    }

    async fn select_pairing_method(
        &mut self,
        _request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        self.select_responses
            .pop_front()
            .ok_or_else(|| BackendError::Transport("unexpected select_pairing_method".into()))
    }

    async fn code_entry_challenge(
        &mut self,
        _request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        Ok(CodeEntryChallengeResponse {
            trezor_cpace_public_key: vec![0xCD; 32],
        })
    }

    async fn send_pairing_tag(
        &mut self,
        request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        match request {
            PairingTagRequest::CodeEntry { code, .. } => {
                if self.expected_code.as_deref() == Some(code.as_str()) {
                    Ok(PairingTagResponse::Accepted {
                        secret: vec![0xEF; 32],
                    })
                } else {
                    Ok(PairingTagResponse::Retry("invalid code".into()))
                }
            }
            _ => Err(BackendError::UnsupportedPairingMethod),
        }
    }

    async fn credential_request(
        &mut self,
        _request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        self.confirmed_connection = true;
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
        if self.completion_state == HandshakeCompletionState::Paired && !self.confirmed_connection {
            return Err(BackendError::Device(
                "session requires connection confirmation".into(),
            ));
        }
        Ok(CreateSessionResponse)
    }

    async fn get_address(
        &mut self,
        request: trezor_connect::thp::GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        let chain = request.chain;
        let address = match chain {
            Chain::Ethereum => "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE",
            Chain::Bitcoin => "bc1qexample000000000000000000000000000000",
            Chain::Solana => "So11111111111111111111111111111111111111112",
        };
        self.last_get_address_request = Some(request);
        Ok(GetAddressResponse {
            chain,
            address: address.into(),
            mac: Some(vec![0xAA; 32]),
            public_key: Some("xpub-test".into()),
        })
    }

    async fn sign_message(
        &mut self,
        request: BackendSignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        let chain = request.chain;
        self.last_sign_message_request = Some(request);
        Ok(SignMessageResponse {
            chain,
            address: match chain {
                Chain::Ethereum => "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE".into(),
                Chain::Bitcoin => "bc1qexample000000000000000000000000000000".into(),
                Chain::Solana => "So11111111111111111111111111111111111111112".into(),
            },
            signature: vec![0x99; 65],
        })
    }

    async fn sign_tx(&mut self, request: BackendSignTxRequest) -> BackendResult<SignTxResponse> {
        self.last_sign_tx_request = Some(request);
        Ok(SignTxResponse {
            chain: Chain::Ethereum,
            v: 0,
            r: vec![0xAA; 32],
            s: vec![0xBB; 32],
        })
    }

    async fn sign_typed_data(
        &mut self,
        request: BackendSignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        let chain = request.chain;
        self.last_sign_typed_data_request = Some(request);
        Ok(SignTypedDataResponse {
            chain,
            address: match chain {
                Chain::Ethereum => "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE".into(),
                Chain::Bitcoin => "bc1qexample000000000000000000000000000000".into(),
                Chain::Solana => "So11111111111111111111111111111111111111112".into(),
            },
            signature: vec![0x77; 65],
        })
    }

    async fn abort(&mut self) -> BackendResult<()> {
        Ok(())
    }
}

fn default_host_config() -> HostConfig {
    let mut config = HostConfig::new("test-host", "hw-core/ffi");
    config.pairing_methods = vec![PairingMethod::CodeEntry];
    config
}

#[tokio::test]
async fn paired_handshake_requires_connection_confirmation_before_session() {
    let backend = MockBackend::paired_requires_confirmation();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    assert_eq!(workflow.state().phase(), Phase::Pairing);
    assert!(workflow.state().is_paired());

    let err = workflow
        .create_session(None, false, false)
        .await
        .expect_err("session should fail before confirmation");
    assert!(
        err.to_string().contains("connection confirmation"),
        "unexpected error: {err}"
    );

    let progress = pairing_confirm_connection_for_workflow(&mut workflow)
        .await
        .expect("confirmation succeeds");
    assert_eq!(progress.kind, crate::types::PairingProgressKind::Completed);

    workflow
        .create_session(None, false, false)
        .await
        .expect("session succeeds after confirmation");
}

#[tokio::test]
async fn code_entry_pairing_submit_completes_pairing() {
    let backend = MockBackend::requires_code_entry_pairing();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    assert_eq!(workflow.state().phase(), Phase::Pairing);
    assert!(!workflow.state().is_paired());

    let prompt = pairing_start_for_state(workflow.state()).expect("pairing prompt");
    assert!(!prompt.requires_connection_confirmation);
    assert!(prompt.available_methods.contains(&PairingMethod::CodeEntry));

    pairing_submit_code_for_workflow(&mut workflow, "123456".into())
        .await
        .expect("pairing completes");
    assert_eq!(workflow.state().phase(), Phase::Paired);
}

#[tokio::test]
async fn typed_address_and_sign_requests_map_to_workflow_calls() {
    let backend = MockBackend::paired_requires_confirmation();
    let mut workflow = ThpWorkflow::new(backend, default_host_config());

    workflow.create_channel().await.unwrap();
    workflow.handshake(false).await.unwrap();
    pairing_confirm_connection_for_workflow(&mut workflow)
        .await
        .unwrap();
    workflow.create_session(None, false, false).await.unwrap();

    let address = get_address_for_workflow(
        &mut workflow,
        GetAddressRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            show_on_device: true,
            include_public_key: true,
            chunkify: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        address.address,
        "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE"
    );

    let signed = sign_tx_for_workflow(
        &mut workflow,
        SignTxRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            to: "0x000000000000000000000000000000000000dead".into(),
            value: "0x0".into(),
            nonce: "0x0".into(),
            gas_limit: "0x5208".into(),
            chain_id: 1,
            data: "0x".into(),
            max_fee_per_gas: "0x3b9aca00".into(),
            max_priority_fee: "0x59682f00".into(),
            access_list: Vec::new(),
            chunkify: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(signed.chain, Chain::Ethereum);
    assert_eq!(signed.v, 0);
    assert_eq!(signed.r.len(), 32);
    assert_eq!(signed.s.len(), 32);

    let signed_message = sign_message_for_workflow(
        &mut workflow,
        SignMessageRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            message: "hello from ffi".into(),
            is_hex: false,
            chunkify: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(signed_message.chain, Chain::Ethereum);
    assert_eq!(signed_message.signature_encoding, SignatureEncoding::Hex);
    assert!(signed_message.signature_formatted.starts_with("0x"));

    let signed_typed_data = sign_typed_data_for_workflow(
        &mut workflow,
        SignTypedDataRequest {
            chain: Chain::Ethereum,
            path: "m/44'/60'/0'/0/0".into(),
            domain_separator_hash:
                "0x1111111111111111111111111111111111111111111111111111111111111111".into(),
            message_hash: Some(
                "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
            ),
            data_json: None,
            metamask_v4_compat: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(signed_typed_data.chain, Chain::Ethereum);
    assert_eq!(signed_typed_data.signature_encoding, SignatureEncoding::Hex);
    assert!(signed_typed_data.signature_formatted.starts_with("0x"));

    let backend = workflow.backend_mut();
    let get_address_request = backend.last_get_address_request.as_ref().unwrap();
    assert_eq!(get_address_request.chain, Chain::Ethereum);
    assert!(get_address_request.show_display);
    assert!(get_address_request.include_public_key);
    assert!(get_address_request.chunkify);

    let sign_request = backend.last_sign_tx_request.as_ref().unwrap();
    assert_eq!(sign_request.chain, Chain::Ethereum);
    assert_eq!(sign_request.chain_id, 1);
    assert_eq!(
        sign_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    let sign_message_request = backend.last_sign_message_request.as_ref().unwrap();
    assert_eq!(sign_message_request.chain, Chain::Ethereum);
    assert_eq!(
        sign_message_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    assert_eq!(sign_message_request.message, b"hello from ffi".to_vec());
    assert!(sign_message_request.chunkify);
    let sign_typed_data_request = backend.last_sign_typed_data_request.as_ref().unwrap();
    assert_eq!(sign_typed_data_request.chain, Chain::Ethereum);
    assert_eq!(
        sign_typed_data_request.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    match &sign_typed_data_request.payload {
        trezor_connect::thp::SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            assert_eq!(*domain_separator_hash, vec![0x11; 32]);
            assert_eq!(*message_hash, Some(vec![0x22; 32]));
        }
        other => panic!("expected hash payload, got {other:?}"),
    }
}

#[test]
fn get_address_request_maps_solana_chain() {
    let mapped = map_get_address_request(GetAddressRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        show_on_device: false,
        include_public_key: true,
        chunkify: true,
    })
    .expect("map request");
    assert_eq!(mapped.chain, Chain::Solana);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_01f5, 0x8000_0000, 0x8000_0000]
    );
    assert!(!mapped.show_display);
    assert!(mapped.include_public_key);
    assert!(mapped.chunkify);
}

#[test]
fn sign_tx_request_maps_solana_chain() {
    let mapped = map_sign_tx_request(SignTxRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: "0x0102030405060708090a0b0c0d0e0f10".into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect("solana request should map");
    assert_eq!(mapped.chain, Chain::Solana);
    assert_eq!(
        mapped.data,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]
    );
}

#[test]
fn sign_tx_request_rejects_too_short_solana_payload() {
    let err = map_sign_tx_request(SignTxRequest {
        chain: Chain::Solana,
        path: "m/44'/501'/0'/0'".into(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: "0x010203".into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect_err("short Solana payload should fail");
    assert!(matches!(err, HWCoreError::Validation(_)));
}

#[test]
fn sign_tx_request_maps_bitcoin_chain() {
    let mapped = map_sign_tx_request(SignTxRequest {
        chain: Chain::Bitcoin,
        path: String::new(),
        to: String::new(),
        value: "0x0".into(),
        nonce: "0x0".into(),
        gas_limit: "0x0".into(),
        chain_id: 0,
        data: BTC_SIGN_WITH_REF_TXS.into(),
        max_fee_per_gas: "0x0".into(),
        max_priority_fee: "0x0".into(),
        access_list: Vec::new(),
        chunkify: false,
    })
    .expect("bitcoin request should map");
    assert_eq!(mapped.chain, Chain::Bitcoin);
    assert!(mapped.btc.is_some());
}

#[test]
fn sign_message_request_maps_ethereum_chain() {
    let mapped = map_sign_message_request(SignMessageRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        message: "hello".into(),
        is_hex: false,
        chunkify: true,
    })
    .expect("message request should map");
    assert_eq!(mapped.chain, Chain::Ethereum);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    assert_eq!(mapped.message, b"hello".to_vec());
    assert!(mapped.chunkify);
}

#[test]
fn sign_message_request_maps_bitcoin_hex_payload() {
    let mapped = map_sign_message_request(SignMessageRequest {
        chain: Chain::Bitcoin,
        path: "m/84'/0'/0'/0/0".into(),
        message: "0x68656c6c6f".into(),
        is_hex: true,
        chunkify: false,
    })
    .expect("message request should map");
    assert_eq!(mapped.chain, Chain::Bitcoin);
    assert_eq!(mapped.message, b"hello".to_vec());
}

#[test]
fn sign_typed_data_request_maps_ethereum_hashes() {
    let mapped = map_sign_typed_data_request(SignTypedDataRequest {
        chain: Chain::Ethereum,
        path: "m/44'/60'/0'/0/0".into(),
        domain_separator_hash: "0x1111111111111111111111111111111111111111111111111111111111111111"
            .into(),
        message_hash: Some(
            "0x2222222222222222222222222222222222222222222222222222222222222222".into(),
        ),
        data_json: None,
        metamask_v4_compat: true,
    })
    .expect("typed-data request should map");
    assert_eq!(mapped.chain, Chain::Ethereum);
    assert_eq!(
        mapped.path,
        vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0]
    );
    match mapped.payload {
        trezor_connect::thp::SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } => {
            assert_eq!(domain_separator_hash, vec![0x11; 32]);
            assert_eq!(message_hash, Some(vec![0x22; 32]));
        }
        other => panic!("expected hash payload, got {other:?}"),
    }
}
