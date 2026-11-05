use super::{LedgerClient, tests::MockTransport};
use crate::LedgerError;
use bitcoin::{
    bip32::DerivationPath,
    hashes::Hash,
    secp256k1::{Message, Secp256k1, SecretKey},
};

fn app() -> Vec<u8> {
    MockTransport::app_info("Bitcoin", "2.4.0")
}

#[tokio::test]
async fn bitcoin_message_continuations_preserve_protocol_status_and_signature() {
    let signature = Secp256k1::new().sign_ecdsa(
        &Message::from_digest([1; 32]),
        &SecretKey::from_slice(&[2; 32]).unwrap(),
    );
    let mut response = vec![31];
    response.extend(signature.serialize_compact());
    response.extend([0x90, 0]);
    // The device requests the committed message leaf, including the Merkle leaf prefix.
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![app(), preimage_request(), response].into(),
        ..Default::default()
    });
    let result = client
        .sign_bitcoin_message(&DerivationPath::from(vec![84u32.into()]), b"test", false)
        .await
        .unwrap();
    assert_eq!(result.1, signature);
    assert!(client.ready);
    assert_eq!(
        client.into_transport().commands[2],
        [0xf8, 1, 0, 1, 7, 5, 5, 0, b't', b'e', b's', b't']
    );
}

#[tokio::test]
async fn bitcoin_rejects_short_final_signatures_after_continuation_and_retires_session() {
    for length in [0, 1, 64, 66] {
        let mut response = vec![0; length];
        response.extend([0x90, 0]);
        let mut client = LedgerClient::new(MockTransport {
            responses: vec![app(), preimage_request(), response].into(),
            ..Default::default()
        });
        assert!(
            client
                .sign_bitcoin_message(&DerivationPath::default(), b"test", false)
                .await
                .is_err()
        );
        assert!(matches!(
            client.app_info().await,
            Err(LedgerError::Disconnected)
        ));
        assert_eq!(client.into_transport().commands.len(), 3);
    }
}

#[tokio::test(start_paused = true)]
async fn bitcoin_cancelled_interpreter_cannot_be_reused() {
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![app(), preimage_request()].into(),
        ..Default::default()
    });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.sign_bitcoin_message(&DerivationPath::default(), b"test", false)
        )
        .await
        .is_err()
    );
    assert!(matches!(
        client.app_info().await,
        Err(LedgerError::Disconnected)
    ));
}

#[tokio::test]
async fn bitcoin_wrong_app_and_rejection_are_actionable() {
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![app()].into(),
        ..Default::default()
    });
    assert!(matches!(
        client.bitcoin_master_fingerprint(true).await,
        Err(LedgerError::WrongApp {
            expected: "Bitcoin Test",
            ..
        })
    ));
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![app(), vec![0x69, 0x85], app(), vec![1, 2, 3, 4, 0x90, 0]].into(),
        ..Default::default()
    });
    assert!(matches!(
        client.bitcoin_master_fingerprint(false).await,
        Err(LedgerError::Rejected)
    ));
    assert_eq!(
        client
            .bitcoin_master_fingerprint(false)
            .await
            .unwrap()
            .as_bytes(),
        &[1, 2, 3, 4]
    );
}

fn preimage_request() -> Vec<u8> {
    let mut bytes = vec![0x40, 0];
    bytes.extend(bitcoin::hashes::sha256::Hash::hash(b"\x00test").to_byte_array());
    bytes.extend([0xe0, 0]);
    bytes
}
