use prost::Message;

use super::*;
use crate::thp::backend::BackendError;
use crate::thp::proto::{
    EthereumDefinitionAck, EthereumDefinitionRequest, EthereumTxAck, EthereumTxRequest,
    MESSAGE_TYPE_SUCCESS, WireMessage,
};
use crate::thp::types::{
    EthDefinitionCatalog, EthDefinitions, EthDisplayFormatDefinition, EthSignTx,
    EthTokenDefinition, EthTxSignature,
};

const PATH: [u32; 5] = [0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
const CHAIN_ID: u64 = 8453;
const TOKEN: [u8; 20] = [0xAA; 20];
const ROUTER: [u8; 20] = [0xBB; 20];
const FUNC_SIG: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn tx_with_catalog() -> EthSignTx {
    EthSignTx::new(PATH.to_vec(), CHAIN_ID)
        .with_data(vec![0xCD; 1500])
        .with_definitions(EthDefinitions {
            encoded_network: Some(b"network".to_vec()),
            ..EthDefinitions::default()
        })
        .with_definition_catalog(EthDefinitionCatalog {
            tokens: vec![EthTokenDefinition {
                address: TOKEN,
                encoded: b"token".to_vec(),
            }],
            display_formats: vec![EthDisplayFormatDefinition {
                address: ROUTER,
                func_sig: FUNC_SIG,
                encoded: b"display".to_vec(),
            }],
        })
}

fn definition_request(chain_id: u64, address: [u8; 20], func_sig: Option<[u8; 4]>) -> Vec<u8> {
    EthereumDefinitionRequest {
        chain_id,
        token_address: address.to_vec(),
        func_sig: func_sig.map(Vec::from),
    }
    .encode_to_vec()
}

fn ack(handling: EthereumTxRequestHandling) -> (u16, Vec<u8>) {
    match handling {
        EthereumTxRequestHandling::Ack(ack) => (ack.message_type, ack.payload),
        EthereumTxRequestHandling::Finished(signature) => {
            panic!("expected an ack, got signature {signature:?}")
        }
    }
}

/// Returns the definitions the host answered with, or `None` for no match.
fn answered_definitions(
    signer: &mut EthereumTxSigner<'_>,
    request: Vec<u8>,
) -> Option<EthDefinitions> {
    let (message_type, payload) = ack(signer
        .handle(EthereumDefinitionRequest::MESSAGE_TYPE, &request)
        .unwrap());
    assert_eq!(message_type, EthereumDefinitionAck::MESSAGE_TYPE);
    EthereumDefinitionAck::decode(payload.as_slice())
        .unwrap()
        .definitions
        .map(|definitions| EthDefinitions {
            encoded_network: definitions.encoded_network,
            encoded_token: definitions.encoded_token,
            encoded_display_format: definitions.encoded_display_format,
        })
}

#[test]
fn answers_definition_requests_between_data_chunks_until_signature() {
    let tx = tx_with_catalog();
    let mut signer = EthereumTxSigner::new(&tx);
    let network = Some(b"network".to_vec());

    assert_eq!(
        answered_definitions(&mut signer, definition_request(CHAIN_ID, TOKEN, None)),
        Some(EthDefinitions {
            encoded_network: network.clone(),
            encoded_token: Some(b"token".to_vec()),
            encoded_display_format: None,
        })
    );
    assert_eq!(
        answered_definitions(
            &mut signer,
            definition_request(CHAIN_ID, ROUTER, Some(FUNC_SIG))
        ),
        Some(EthDefinitions {
            encoded_network: network,
            encoded_token: None,
            encoded_display_format: Some(b"display".to_vec()),
        })
    );

    let data_request = EthereumTxRequest {
        data_length: Some(1024),
        ..EthereumTxRequest::default()
    }
    .encode_to_vec();
    let (message_type, payload) = ack(signer
        .handle(EthereumTxRequest::MESSAGE_TYPE, &data_request)
        .unwrap());
    assert_eq!(message_type, EthereumTxAck::MESSAGE_TYPE);
    assert_eq!(
        EthereumTxAck::decode(payload.as_slice()).unwrap(),
        EthereumTxAck::new(&[0xCD; 1500 - 1024])
    );

    let signature = EthereumTxRequest {
        data_length: None,
        signature_v: Some(1),
        signature_r: Some(vec![0x11; 32]),
        signature_s: Some(vec![0x22; 32]),
    }
    .encode_to_vec();
    assert!(matches!(
        signer.handle(EthereumTxRequest::MESSAGE_TYPE, &signature),
        Ok(EthereumTxRequestHandling::Finished(EthTxSignature { v: 1, r, s }))
            if r == [0x11; 32] && s == [0x22; 32]
    ));
}

#[test]
fn answers_without_definitions_when_nothing_matches() {
    let tx = tx_with_catalog();
    let mut signer = EthereumTxSigner::new(&tx);
    for request in [
        definition_request(CHAIN_ID, [0xEE; 20], None),
        definition_request(CHAIN_ID, ROUTER, None),
        definition_request(CHAIN_ID, ROUTER, Some([0xFF; 4])),
        definition_request(1, TOKEN, None),
    ] {
        assert_eq!(answered_definitions(&mut signer, request), None);
    }
}

#[test]
fn rejects_unexpected_device_message() {
    let tx = tx_with_catalog();
    let mut signer = EthereumTxSigner::new(&tx);
    assert!(matches!(
        signer.handle(MESSAGE_TYPE_SUCCESS, &[]),
        Err(BackendError::Transport(_))
    ));
}
