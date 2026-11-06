use super::*;
use crate::eth::TxInput;
use k256::ecdsa::SigningKey;
use ledger_connect::LedgerClient;
type Mock = ledger_connect::testing::ScriptedTransport;
use sha3::{Digest, Keccak256};
use std::collections::VecDeque;

const ADDRESS: &str = "5637C997D8aFf61a4EC7d606f461c1c75f2b8120";
const TX: &str = r#"{"to":"0x000000000000000000000000000000000000dead","nonce":"0x1","gas_limit":"0x5208","max_fee_per_gas":"0x1","max_priority_fee":"0x1","chain_id":1}"#;

fn signing_mock(hash: [u8; 32], address: &str) -> Mock {
    let key = SigningKey::from_slice(
        &hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279ef4f8f6f1842f5f6d4").unwrap(),
    )
    .unwrap();
    let (signature, recovery) = key.sign_prehash_recoverable(&hash);
    let mut signed = vec![recovery.to_byte() + 27];
    signed.extend(signature.to_bytes());
    signed.extend([0x90, 0]);
    let app = Mock::app_info("Ethereum", "1.0.0");
    let mut account = vec![65];
    account.extend(key.verifying_key().to_sec1_point(false).as_bytes());
    account.push(40);
    account.extend(address.as_bytes());
    account.extend([0x90, 0]);
    Mock {
        responses: vec![app.clone(), account, app, signed].into(),
        commands: vec![],
    }
}

#[tokio::test]
async fn eip1559_uses_known_rlp_envelope_and_assembles_verified_signed_transaction() {
    let unsigned =
        hex::decode("02df0101010182520894000000000000000000000000000000000000dead8080c0").unwrap();
    let hash: [u8; 32] = Keccak256::digest(&unsigned).into();
    let mut client = LedgerClient::new(signing_mock(hash, ADDRESS));
    let request = TxInput::from_json(TX)
        .unwrap()
        .into_sign_tx(vec![1])
        .unwrap();
    let result = client.sign_eip1559(&request).await.unwrap();
    assert_eq!(result.recovered_address, format!("0x{ADDRESS}"));
    assert_eq!(result.signing_hash, hash);
    let signed = result.signed_transaction.unwrap();
    assert_eq!(signed[0], 2);
    let list = rlp::Rlp::new(&signed[1..]);
    assert_eq!(list.item_count().unwrap(), 12);
    let original = rlp::Rlp::new(&unsigned[1..]);
    for index in 0..9 {
        assert_eq!(
            list.at(index).unwrap().as_raw(),
            original.at(index).unwrap().as_raw()
        );
    }
    assert!(list.val_at::<u8>(9).unwrap() <= 1);
    assert_eq!(
        result.transaction_hash.unwrap(),
        Keccak256::digest(&signed).to_vec()
    );
    let transport = client.into_transport();
    assert_eq!(&transport.commands[3][10..], unsigned);
}

#[tokio::test]
async fn personal_message_recovery_rejects_changed_message_and_wrong_account() {
    let hash: [u8; 32] = Keccak256::digest(b"\x19Ethereum Signed Message:\n5hello").into();
    for (message, address, accepted) in [
        (b"hello".as_slice(), ADDRESS, true),
        (b"world".as_slice(), ADDRESS, false),
        (
            b"hello".as_slice(),
            "0000000000000000000000000000000000000001",
            false,
        ),
    ] {
        let mut client = LedgerClient::new(signing_mock(hash, address));
        let request = trezor_connect::thp::SignMessageRequest::ethereum(vec![1], message.to_vec());
        let result = client.sign_message(&request).await;
        assert_eq!(result.is_ok(), accepted);
        if let Err(error) = &result {
            assert_eq!(error.kind(), crate::WalletErrorKind::Device);
        }
        if let Ok(result) = result {
            assert!(matches!(result.signature[64], 27 | 28));
            assert!(result.signed_data.is_none());
        }
    }
}

#[tokio::test]
async fn invalid_transaction_is_rejected_before_device_interaction() {
    for case in 0..4 {
        let mut request = TxInput::from_json(TX)
            .unwrap()
            .into_sign_tx(vec![1])
            .unwrap();
        match case {
            0 => request.chain_id = 0,
            1 => request.value = vec![1; 33],
            2 => request.to = "0xdead".into(),
            _ => request.definitions.encoded_network = Some(vec![1]),
        }
        let mut client = LedgerClient::new(Mock {
            responses: VecDeque::new(),
            commands: vec![],
        });
        assert!(client.sign_eip1559(&request).await.is_err());
        assert!(client.into_transport().commands.is_empty());
    }
}

const MAIL: &str = include_str!("../../../../tests/data/ethereum/eip712_mail.json");
const ETH_PATH: &[u32] = &[0x8000002c, 0x8000003c, 0x80000000, 0, 0];
const SOL_PATH: &[u32] = &[0x8000002c, 0x800001f5, 0x80000000, 0x80000000];

#[test]
fn full_eip712_matches_official_mail_vector_and_rejects_malformed_fields() {
    use crate::message::SignTypedDataRequestExt;
    use trezor_connect::thp::{SignTypedDataPayload, SignTypedDataRequest};
    let request = SignTypedDataRequest::from_eip712_json(ETH_PATH.to_vec(), MAIL, true).unwrap();
    let SignTypedDataPayload::TypedData(data) = request.payload else {
        panic!()
    };
    let prepared = super::prepared_typed_data::PreparedTypedData::new(&data).unwrap();
    assert_eq!(
        hex::encode(prepared.hash),
        "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
    );
    for replacement in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!([1]),
        serde_json::json!("invalid"),
        serde_json::json!("0x1"),
    ] {
        let mut data = data.clone();
        data.message["from"]["wallet"] = replacement;
        assert!(super::prepared_typed_data::PreparedTypedData::new(&data).is_err());
    }
    // Custom struct names may start with a primitive type's spelling.
    let mut named = data.clone();
    let person = named.types.remove("Person").unwrap();
    named.types.insert("integer".into(), person);
    for field in named.types.get_mut("Mail").unwrap() {
        if field.type_name == "Person" {
            field.type_name = "integer".into();
        }
    }
    assert_eq!(
        hex::encode(
            super::prepared_typed_data::PreparedTypedData::new(&named)
                .unwrap()
                .hash
        ),
        "a2953003f89119acf8bc391865ab6afed23d1a1f29f47ac2807d83dfdad1f296"
    );
    let mut data = data;
    let duplicate = data.types["Mail"][0].clone();
    data.types.get_mut("Mail").unwrap().push(duplicate);
    assert!(super::prepared_typed_data::PreparedTypedData::new(&data).is_err());
}

#[tokio::test]
async fn eip712_hashes_verify_signer_and_never_sign_missing_message_hash() {
    use crate::message::SignTypedDataRequestExt;
    use trezor_connect::thp::SignTypedDataRequest;
    let request = SignTypedDataRequest::from_eip712_hashes(
        ETH_PATH.to_vec(),
        &"11".repeat(32),
        Some(&"22".repeat(32)),
    )
    .unwrap();
    let mut hash = Keccak256::new();
    hash.update([0x19, 1]);
    hash.update([0x11; 32]);
    hash.update([0x22; 32]);
    let hash: [u8; 32] = hash.finalize().into();
    let mut client = LedgerClient::new(signing_mock(hash, ADDRESS));
    let result = client.sign_verified_typed_data(&request).await.unwrap();
    assert_eq!(result.signature.len(), 65);
    assert!(matches!(result.signature[64], 27 | 28));
    assert_eq!(
        &client.into_transport().commands[3][..5],
        &[0xe0, 0x0c, 0, 0, 85]
    );
    let mut client = LedgerClient::new(signing_mock([9; 32], ADDRESS));
    assert!(client.sign_verified_typed_data(&request).await.is_err());
    let request =
        SignTypedDataRequest::from_eip712_hashes(ETH_PATH.to_vec(), &"11".repeat(32), None)
            .unwrap();
    let mut client = LedgerClient::new(Mock {
        responses: VecDeque::new(),
        commands: vec![],
    });
    assert!(client.sign_verified_typed_data(&request).await.is_err());
    assert!(client.into_transport().commands.is_empty());
}

#[tokio::test]
async fn solana_verifies_exact_transaction_and_sorted_ocms_envelope() {
    use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
    use trezor_connect::thp::{SignMessageRequest, SolanaSignTx};
    let key = EdSigningKey::from_bytes(&[3; 32]);
    let public = key.verifying_key().to_bytes();
    let app = Mock::app_info("Solana", "1.0.0");
    let mock = |message: &[u8], wrong: bool| {
        let mut account = public.to_vec();
        account.extend([0x90, 0]);
        let mut signature = key
            .sign(if wrong { b"wrong" } else { message })
            .to_bytes()
            .to_vec();
        signature.extend([0x90, 0]);
        Mock {
            responses: vec![app.clone(), account, app.clone(), signature].into(),
            commands: vec![],
        }
    };
    let tx = SolanaSignTx {
        path: SOL_PATH.to_vec(),
        serialized_tx: [vec![1, 0, 0, 1], public.to_vec(), vec![0; 32], vec![0]].concat(),
        additional_info: None,
    };
    for wrong in [false, true] {
        let mut client = LedgerClient::new(mock(&tx.serialized_tx, wrong));
        assert_eq!(client.sign_tx(&tx.clone().into()).await.is_err(), wrong);
    }
    let mut signers = vec![[0; 32], public];
    signers.sort();
    let mut expected = b"\xffsolana offchain\x01\x02".to_vec();
    for key in &signers {
        expected.extend(key);
    }
    expected.extend("Hello 🌍".as_bytes());
    signers.reverse();
    let request = SignMessageRequest::solana(SOL_PATH.to_vec(), "Hello 🌍".into(), signers);
    let mut client = LedgerClient::new(mock(&expected, false));
    let result = client.sign_verified_solana_message(&request).await.unwrap();
    assert_eq!(result.signed_data, Some(expected.clone()));
    assert_eq!(result.address, bs58::encode(public).into_string());
    let commands = client.into_transport().commands;
    assert_eq!(&commands[3][..4], &[0xe0, 7, 1, 0]);
    assert_eq!(&commands[3][23..], &expected);
    let mut client = LedgerClient::new(mock(&expected, true));
    assert!(client.sign_verified_solana_message(&request).await.is_err());

    let mut old_app = mock(&expected, false);
    *old_app.responses.back_mut().unwrap() = vec![0x6a, 0x81];
    let mut client = LedgerClient::new(old_app);
    let error = client
        .sign_verified_solana_message(&request)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("OCMS v1 support"));
    assert_eq!(error.kind(), crate::WalletErrorKind::Unsupported);
    // A legacy-only app must not cause a retry with different signed bytes.
    assert_eq!(client.into_transport().commands.len(), 4);
}

#[test]
fn eip712_nested_arrays_signed_integers_and_dynamic_bytes_match_ethers_vector() {
    use crate::message::SignTypedDataRequestExt;
    use trezor_connect::thp::{SignTypedDataPayload, SignTypedDataRequest};
    let request = SignTypedDataRequest::from_eip712_json(
        ETH_PATH.to_vec(),
        include_str!("../../../../tests/data/ethereum/eip712_nested.json"),
        true,
    )
    .unwrap();
    let SignTypedDataPayload::TypedData(data) = request.payload else {
        panic!()
    };
    let prepared = super::prepared_typed_data::PreparedTypedData::new(&data).unwrap();
    assert_eq!(
        hex::encode(prepared.hash),
        "b44ed86c49e9255e4ff0f7f70b44ef4344af7e76fc94c1ed5edb466d9391eeb1"
    );
    let definition = super::eip712_field::Eip712Field::parse("int16[2][]")
        .unwrap()
        .definition("scores")
        .unwrap();
    assert_eq!(definition, b"\xc1\x02\x02\x01\x02\x00\x06scores");
    for value in [
        serde_json::json!([[1]]),
        serde_json::json!([[32768, 0]]),
        serde_json::json!([[0, -32769]]),
    ] {
        let mut bad = data.clone();
        bad.message["scores"] = value;
        assert!(super::prepared_typed_data::PreparedTypedData::new(&bad).is_err());
    }
}

#[tokio::test]
async fn full_typed_data_stream_is_verified_without_hash_only_fallback() {
    use crate::message::SignTypedDataRequestExt;
    use trezor_connect::thp::SignTypedDataRequest;
    let request = SignTypedDataRequest::from_eip712_json(ETH_PATH.to_vec(), MAIL, true).unwrap();
    let hash = hex::decode("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
        .unwrap()
        .try_into()
        .unwrap();
    for valid in [true, false] {
        let mut mock = signing_mock(if valid { hash } else { [0; 32] }, ADDRESS);
        let signed = mock.responses.pop_back().unwrap();
        mock.responses
            .extend(std::iter::repeat_n(vec![0x90, 0], 23));
        mock.responses.push_back(signed);
        let mut client = LedgerClient::new(mock);
        let result = client.sign_verified_typed_data(&request).await;
        assert_eq!(result.is_ok(), valid);
        let commands = client.into_transport().commands;
        assert_eq!(commands.len(), 27);
        assert_eq!(&commands.last().unwrap()[..4], &[0xe0, 0x0c, 0, 1]);
    }
}

#[tokio::test]
async fn solana_rejects_full_transaction_envelopes_and_malformed_messages_before_device_io() {
    let mut message = vec![1, 0, 0, 1];
    message.extend([3; 32]);
    message.extend([0; 32]);
    message.push(0);
    let wrapped = [vec![1], vec![0; 64], message.clone()].concat();
    let mut trailing = message.clone();
    trailing.push(0);
    let mut truncated = message.clone();
    truncated.pop();
    let mut invalid_header = message.clone();
    invalid_header[0] = 2;
    for bytes in [wrapped, trailing, truncated, invalid_header] {
        let mut client = LedgerClient::new(Mock {
            responses: VecDeque::new(),
            commands: vec![],
        });
        let request = trezor_connect::thp::SolanaSignTx {
            path: SOL_PATH.to_vec(),
            serialized_tx: bytes,
            additional_info: None,
        };
        let error = client
            .sign_verified_solana_transaction(&request)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), crate::WalletErrorKind::Validation);
        assert!(client.into_transport().commands.is_empty());
    }
    crate::sol::SolanaMessage::required_signers(&message).unwrap();
    let versioned = [vec![0x80], message, vec![0]].concat();
    crate::sol::SolanaMessage::required_signers(&versioned).unwrap();
}

#[tokio::test]
async fn official_ledger_eip712_streams_match_struct_arrays_dependencies_and_wide_signed_ints() {
    use crate::message::SignTypedDataRequestExt;
    use trezor_connect::thp::{SignTypedDataPayload, SignTypedDataRequest};
    for (json, recording, expected_hash) in [
        (
            include_str!("../../../../tests/data/ethereum/ledger/6.json"),
            include_str!("../../../../tests/data/ethereum/ledger/6.apdus"),
            "eb39729929b718f017fa7e39a3bb451357d5bc6d28b8c73f4f1b7f39f13afb09",
        ),
        (
            include_str!("../../../../tests/data/ethereum/ledger/13.json"),
            include_str!("../../../../tests/data/ethereum/ledger/13.apdus"),
            "e09868a20d323de3c8543dba9adaeb79fcdc8a6144d029c2e3af18be6ae20d94",
        ),
    ] {
        let request =
            SignTypedDataRequest::from_eip712_json(ETH_PATH.to_vec(), json, true).unwrap();
        let SignTypedDataPayload::TypedData(data) = request.payload else {
            panic!("full typed data")
        };
        let prepared = super::prepared_typed_data::PreparedTypedData::new(&data).unwrap();
        assert_eq!(hex::encode(prepared.hash), expected_hash);
        let expected: Vec<Vec<u8>> = recording
            .lines()
            .filter_map(|line| line.strip_prefix("=> "))
            .map(|line| hex::decode(line.trim()).unwrap())
            .collect();
        let mut responses = VecDeque::from([Mock::app_info("Ethereum", "1.0.0")]);
        responses.extend(
            recording
                .lines()
                .filter_map(|line| line.strip_prefix("<= "))
                .map(|line| hex::decode(line.trim()).unwrap()),
        );
        let mut client = LedgerClient::new(Mock {
            responses,
            commands: vec![],
        });
        client
            .sign_eip712(ETH_PATH, &prepared.commands)
            .await
            .unwrap();
        assert_eq!(client.into_transport().commands[1..], expected);
    }
}

#[tokio::test]
async fn shared_ledger_requests_reject_unsupported_options_before_device_io() {
    use trezor_connect::thp::{GetAddressRequest, SignMessageRequest};
    for chain in [
        hw_chain::Chain::Bitcoin,
        hw_chain::Chain::Ethereum,
        hw_chain::Chain::Solana,
    ] {
        for (chunkify, network) in [(true, None), (false, Some(vec![1]))] {
            let mut client = LedgerClient::new(Mock::default());
            let mut address = GetAddressRequest::ethereum(ETH_PATH.to_vec());
            address.chain = chain;
            address.chunkify = chunkify;
            address.encoded_network = network.clone();
            assert_eq!(
                client.get_address(&address).await.unwrap_err().kind(),
                crate::WalletErrorKind::Unsupported
            );
            let mut message = SignMessageRequest::ethereum(ETH_PATH.to_vec(), b"hello".to_vec());
            message.chain = chain;
            message.chunkify = chunkify;
            message.encoded_network = network;
            assert_eq!(
                client.sign_message(&message).await.unwrap_err().kind(),
                crate::WalletErrorKind::Unsupported
            );
            assert!(client.into_transport().commands.is_empty());
        }
    }
}

#[tokio::test]
async fn solana_requires_the_derived_key_in_the_static_required_signers() {
    let key = [7; 32];
    for versioned in [false, true] {
        // The derived key is present, but only as an unsigned account.
        let mut bytes = if versioned { vec![0x80] } else { vec![] };
        bytes.extend([1, 0, 1, 2]);
        bytes.extend([8; 32]);
        bytes.extend(key);
        bytes.extend([0; 32]);
        bytes.push(0);
        if versioned {
            bytes.push(0);
        }
        let mut response = key.to_vec();
        response.extend([0x90, 0]);
        let mut client = LedgerClient::new(Mock {
            responses: vec![Mock::app_info("Solana", "1.17.1"), response].into(),
            commands: vec![],
        });
        let request = trezor_connect::thp::SolanaSignTx {
            path: SOL_PATH.to_vec(),
            serialized_tx: bytes,
            additional_info: None,
        };
        let error = client
            .sign_verified_solana_transaction(&request)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not a required transaction signer")
        );
        assert_eq!(client.into_transport().commands.len(), 2);
    }
}

#[tokio::test]
async fn solana_ocms_v1_matches_independent_openssl_signature_vector() {
    // Format checked against app-solana's V1OffchainMessage.serialize. Signature generated
    // independently with Node/OpenSSL Ed25519, using the public test seed [7; 32].
    let key =
        hex::decode("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c").unwrap();
    let envelope = hex::decode("ff736f6c616e61206f6666636861696e0101ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c54657374206d657373616765").unwrap();
    let signature = hex::decode("4b992ced441e8f75bfdc3b8152e3f2a78924fc0f7ae4199f431565b027860de7b85012288d60aa79a15ad1fd7fdc7c5ecae7077c3925be36c3f7754787a5f708").unwrap();
    let app = Mock::app_info("Solana", "1.17.1");
    let mut key_response = key.clone();
    key_response.extend([0x90, 0]);
    let mut signed_response = signature.clone();
    signed_response.extend([0x90, 0]);
    let mut client = LedgerClient::new(Mock {
        responses: vec![app.clone(), key_response, app, signed_response].into(),
        commands: vec![],
    });
    let request = trezor_connect::thp::SignMessageRequest::solana(
        SOL_PATH.to_vec(),
        "Test message".into(),
        vec![],
    );
    let result = client.sign_message(&request).await.unwrap();
    assert_eq!(result.signature, signature);
    assert_eq!(result.signed_data, Some(envelope.clone()));
    let mut expected = hex::decode("e00701005001048000002c800001f58000000080000000").unwrap();
    expected.extend(envelope);
    assert_eq!(client.into_transport().commands[3], expected);
}
