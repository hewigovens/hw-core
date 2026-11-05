use super::*;
use crate::LedgerError;

use crate::testing::ScriptedTransport;
pub(super) type MockTransport = ScriptedTransport<true>;

#[tokio::test]
async fn address_encodes_path_and_chain_id_and_parses_device_response() {
    let mut response = vec![65, 4];
    response.extend([0x11; 64]);
    response.push(40);
    response.extend_from_slice(b"1234567890abcdef1234567890abcdef12345678");
    response.extend([0x90, 0]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![ethereum_app_response(), response].into(),
        ..Default::default()
    });
    let address = client
        .ethereum_address(&[0x8000002c, 0x8000003c, 0x80000000, 0, 0], true, 1)
        .await
        .unwrap();
    assert_eq!(
        address.address,
        "0x1234567890abcdef1234567890abcdef12345678"
    );
    assert_eq!(
        client.into_transport().commands[1..],
        vec![vec![
            0xe0, 2, 1, 0, 29, 5, 0x80, 0, 0, 44, 0x80, 0, 0, 60, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]]
    );
}

#[tokio::test]
async fn personal_message_chunks_include_length_and_continuation_flag() {
    let mut signature = vec![27];
    signature.extend([0x11; 32]);
    signature.extend([0x22; 32]);
    signature.extend([0x90, 0]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![ethereum_app_response(), vec![0x90, 0], signature].into(),
        ..Default::default()
    });
    let result = client
        .sign_personal_message(&[0x8000002c], &[0x41; 200])
        .await
        .unwrap();
    assert_eq!(result.v, 27);
    assert_eq!(result.r, vec![0x11; 32]);
    let commands = client.into_transport().commands;
    assert_eq!(
        &commands[1][..14],
        &[0xe0, 8, 0, 0, 150, 1, 0x80, 0, 0, 44, 0, 0, 0, 200]
    );
    assert_eq!(&commands[2][..5], &[0xe0, 8, 0x80, 0, 59]);
    assert!(commands[2][5..].iter().all(|byte| *byte == 0x41));
}

#[tokio::test]
async fn malformed_status_and_signature_fail_without_sending_another_request() {
    for response in [vec![], vec![0x90], vec![0x90, 0], vec![1, 0x90, 0]] {
        let mut client = LedgerClient::new(MockTransport {
            responses: vec![ethereum_app_response(), response].into(),
            ..Default::default()
        });
        assert!(client.sign_transaction(&[1], &[2, 0xc0]).await.is_err());
        assert!(matches!(
            client.ethereum_address(&[1], false, 1).await,
            Err(LedgerError::Disconnected)
        ));
        assert_eq!(client.into_transport().commands.len(), 2);
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_signing_does_not_allow_a_new_command_on_the_session() {
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![ethereum_app_response(), vec![0x90, 0]].into(),
        ..Default::default()
    });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.sign_personal_message(&[1], &[0x41; 200])
        )
        .await
        .is_err()
    );
    assert!(matches!(
        client.ethereum_address(&[1], false, 1).await,
        Err(LedgerError::Disconnected)
    ));
    assert_eq!(client.into_transport().commands.len(), 3);
}

#[tokio::test]
async fn invalid_paths_never_reach_transport() {
    let mut client = LedgerClient::new(MockTransport::default());
    for path in [vec![], vec![1; 11]] {
        assert!(matches!(
            client.ethereum_address(&path, true, 1).await,
            Err(LedgerError::InvalidBip32Path(_))
        ));
    }
    assert!(client.into_transport().commands.is_empty());
}

fn ethereum_app_response() -> Vec<u8> {
    MockTransport::app_info("Ethereum", "1.0.0")
}

#[tokio::test]
async fn wrong_app_and_malformed_app_info_never_send_ethereum_commands() {
    for response in [
        b"\x01\x07Bitcoin\x051.0.0\x90\x00".to_vec(),
        vec![1, 10, b'E', 0x90, 0],
    ] {
        let mut client = LedgerClient::new(MockTransport {
            responses: vec![response].into(),
            ..Default::default()
        });
        assert!(client.ethereum_address(&[1], false, 1).await.is_err());
        assert_eq!(
            client.into_transport().commands,
            vec![vec![0xb0, 1, 0, 0, 0]]
        );
    }
}

#[tokio::test]
async fn transaction_payload_is_sent_without_a_message_length_prefix() {
    let mut response = vec![1];
    response.extend([0x11; 32]);
    response.extend([0x22; 32]);
    response.extend([0x90, 0]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![ethereum_app_response(), response].into(),
        ..Default::default()
    });
    let transaction = [2, 0xc9, 1, 0x80, 1, 1, 1, 0x80, 0x80, 0x80, 0xc0];
    let signature = client
        .sign_transaction(&[0x8000002c], &transaction)
        .await
        .unwrap();
    assert_eq!(signature.v, 1);
    assert_eq!(
        client.into_transport().commands[1],
        vec![
            0xe0, 4, 0, 0, 16, 1, 0x80, 0, 0, 44, 2, 0xc9, 1, 0x80, 1, 1, 1, 0x80, 0x80, 0x80, 0xc0
        ]
    );
}

#[tokio::test]
async fn solana_commands_use_path_confirmation_and_p2_chunking() {
    let app = b"\x01\x06Solana\x051.0.0\x90\x00".to_vec();
    let mut key = vec![7; 32];
    key.extend([0x90, 0]);
    let mut sig = vec![9; 64];
    sig.extend([0x90, 0]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![app.clone(), key, app, vec![0x90, 0], vec![0x90, 0], sig].into(),
        ..Default::default()
    });
    let path = [0x8000002c, 0x800001f5, 0x80000000, 0x80000000];
    assert_eq!(
        client.solana_public_key(&path, true).await.unwrap(),
        [7; 32]
    );
    assert_eq!(
        client
            .sign_solana_transaction(&path, &[0x55; 510])
            .await
            .unwrap(),
        [9; 64]
    );
    let commands = client.into_transport().commands;
    assert_eq!(&commands[1][..5], &[0xe0, 5, 1, 0, 17]);
    assert_eq!(&commands[3][..7], &[0xe0, 6, 1, 2, 255, 1, 4]);
    assert_eq!(&commands[4][..5], &[0xe0, 6, 1, 3, 255]);
    assert_eq!(&commands[5][..5], &[0xe0, 6, 1, 1, 18]);
    assert_eq!(
        commands[3..]
            .iter()
            .flat_map(|c| c[5..].iter().copied())
            .collect::<Vec<_>>()[18..],
        [0x55; 510]
    );
}

#[tokio::test(start_paused = true)]
async fn eip712_streams_field_lengths_and_cancellation_retires_client() {
    let fields = [
        Eip712Command::StructName("Mail".into()),
        Eip712Command::Root("Mail".into()),
        Eip712Command::Value(vec![0x41; 300]),
    ];
    let mut sig = vec![27; 65];
    sig.extend([0x90, 0]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![
            ethereum_app_response(),
            vec![0x90, 0],
            vec![0x90, 0],
            vec![0x90, 0],
            vec![0x90, 0],
            sig,
        ]
        .into(),
        ..Default::default()
    });
    client.sign_eip712(&[0x8000002c], &fields).await.unwrap();
    let commands = client.into_transport().commands;
    assert_eq!(commands[1], b"\xe0\x1a\0\0\x04Mail");
    assert_eq!(&commands[3][..7], &[0xe0, 0x1c, 1, 0xff, 255, 1, 44]);
    assert_eq!(&commands[4][..5], &[0xe0, 0x1c, 0, 0xff, 47]);
    assert_eq!(&commands[5][..5], &[0xe0, 0x0c, 0, 1, 5]);
    let mut client = LedgerClient::new(MockTransport {
        responses: vec![ethereum_app_response(), vec![0x90, 0]].into(),
        ..Default::default()
    });
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.sign_eip712(&[0x8000002c], &fields)
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
async fn completed_device_errors_allow_the_next_request_on_the_same_session() {
    for status in [0x6985u16, 0x6982, 0x5515, 0x6a80] {
        for operation in 0..7 {
            let app = if operation >= 4 {
                b"\x01\x06Solana\x051.0.0\x90\x00".to_vec()
            } else {
                ethereum_app_response()
            };
            let mut client = LedgerClient::new(MockTransport {
                responses: vec![app.clone(), status.to_be_bytes().to_vec(), app].into(),
                ..Default::default()
            });
            let path = [0x8000002c, 0x800001f5, 0x80000000, 0x80000000];
            let result = match operation {
                0 => client.ethereum_address(&[1], true, 1).await.map(|_| ()),
                1 => client
                    .sign_personal_message(&[1], b"test")
                    .await
                    .map(|_| ()),
                2 => client
                    .sign_eip712_hashes(&[1], &[0; 32], &[1; 32])
                    .await
                    .map(|_| ()),
                3 => client
                    .sign_eip712(&[1], &[Eip712Command::StructName("Mail".into())])
                    .await
                    .map(|_| ()),
                4 => client.solana_public_key(&path, true).await.map(|_| ()),
                5 => client
                    .sign_solana_transaction(&path, &[1; 300])
                    .await
                    .map(|_| ()),
                _ => client
                    .sign_solana_offchain_message(&path, b"test")
                    .await
                    .map(|_| ()),
            };
            assert!(result.is_err(), "operation {operation}, status {status:x}");
            client
                .app_info()
                .await
                .expect("completed device status must preserve the session");
            assert_eq!(client.into_transport().commands.len(), 3);
        }
    }
}

#[tokio::test]
async fn legacy_ethereum_envelopes_are_rejected_before_device_io() {
    let mut client = LedgerClient::new(MockTransport::default());
    for transaction in [vec![], vec![0xc0], vec![1, 0xc0]] {
        assert!(matches!(
            client.sign_transaction(&[1], &transaction).await,
            Err(LedgerError::InvalidInput(_))
        ));
    }
    assert!(client.into_transport().commands.is_empty());
}

#[tokio::test]
async fn solana_statuses_are_typed_and_leave_completed_sessions_reusable() {
    for (status, blind) in [(vec![0x68, 0x08], true), (vec![0x6a, 0x81], false)] {
        let app = MockTransport::app_info("Solana", "1.17.1");
        let mut client = LedgerClient::new(MockTransport {
            responses: vec![app.clone(), status, app].into(),
            commands: vec![],
        });
        let error = client
            .sign_solana_offchain_message(&[0x8000002c, 0x800001f5], b"message")
            .await
            .unwrap_err();
        if blind {
            assert!(matches!(error, LedgerError::SolanaBlindSigningRequired));
        } else {
            assert!(matches!(error, LedgerError::SolanaMessageHeaderUnsupported));
        }
        assert!(client.is_ready());
        client.app_info().await.unwrap();
    }
}

#[tokio::test]
async fn ethereum_mid_stream_rejection_allows_a_successful_next_request() {
    for status in [0x6985u16, 0x6982] {
        let mut client = LedgerClient::new(MockTransport {
            responses: vec![
                ethereum_app_response(),
                vec![0x90, 0],
                status.to_be_bytes().to_vec(),
                ethereum_app_response(),
            ]
            .into(),
            commands: vec![],
        });
        assert!(matches!(
            client.sign_personal_message(&[1], &[0x41; 400]).await,
            Err(LedgerError::Rejected)
        ));
        assert!(client.is_ready());
        assert_eq!(client.app_info().await.unwrap().name, "Ethereum");
        let commands = client.into_transport().commands;
        assert_eq!(commands.len(), 4);
        assert_eq!(&commands[1][..5], &[0xe0, 0x08, 0, 0, 150]);
        assert_eq!(&commands[2][..5], &[0xe0, 0x08, 0x80, 0, 150]);
        assert_eq!(commands[3], [0xb0, 1, 0, 0, 0]);
    }
}
