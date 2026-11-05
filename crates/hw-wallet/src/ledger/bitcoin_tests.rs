use super::{
    LedgerBitcoinExt, LedgerWalletExt, bitcoin_account::BitcoinAccount,
    bitcoin_transaction::BitcoinTransaction,
};
use bitcoin::{
    EcdsaSighashType, Network,
    bip32::{Xpriv, Xpub},
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
};
use ledger_bitcoin_client::{
    PartialSignature, SignPsbtYieldedObject, WalletPolicy, wallet::Version,
};
use ledger_connect::LedgerClient;
type Mock = ledger_connect::testing::ScriptedTransport;
use std::collections::VecDeque;
use trezor_connect::thp::{BtcSignTx, SignMessageRequest};

fn fixture() -> (BitcoinAccount, BtcSignTx, Xpriv) {
    let path = vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0];
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Bitcoin, &[1; 32]).unwrap();
    let private = master
        .derive_priv(&secp, &BitcoinAccount::derivation(&path[..3]))
        .unwrap();
    let xpub = Xpub::from_priv(&secp, &private);
    let fingerprint = master.fingerprint(&secp);
    let account = BitcoinAccount {
        purpose: super::bitcoin_purpose::BitcoinPurpose::Segwit,
        path: path[..3].to_vec(),
        network: Network::Bitcoin,
        fingerprint,
        xpub,
        policy: WalletPolicy::new(
            String::new(),
            Version::V2,
            "wpkh(@0/**)".into(),
            [((fingerprint, BitcoinAccount::derivation(&path[..3])), xpub)],
        ),
    };
    let script = account.address(&path).unwrap().script_pubkey();
    let reference = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(10000),
            script_pubkey: script.clone(),
        }],
    };
    let txid = reference.compute_txid().to_string();
    let json = serde_json::json!({"inputs":[{"path":"m/84'/0'/0'/0/0","prev_hash":txid,"prev_index":0,"amount":"10000"}],"outputs":[{"path":"m/84'/0'/0'/1/0","amount":"9000"}],"ref_txs":[{"hash":txid,"version":2,"lock_time":0,"inputs":[{"prev_hash":"00".repeat(32),"prev_index":4294967295u32,"script_sig":""}],"bin_outputs":[{"amount":"10000","script_pubkey":hex::encode(script.as_bytes())}]}]});
    let request = crate::btc::TxInput::from_json(&json.to_string())
        .unwrap()
        .try_into()
        .unwrap();
    (account, request, private)
}

fn signatures(
    prepared: &BitcoinTransaction,
    private: &Xpriv,
) -> Vec<(usize, SignPsbtYieldedObject)> {
    let secp = Secp256k1::new();
    let key = private
        .derive_priv(&secp, &BitcoinAccount::derivation(&[0, 0]))
        .unwrap();
    (0..prepared.psbt.inputs.len())
        .map(|index| {
            let previous = prepared.psbt.inputs[index].witness_utxo.as_ref().unwrap();
            let hash = SighashCache::new(&prepared.psbt.unsigned_tx)
                .p2wpkh_signature_hash(
                    index,
                    &previous.script_pubkey,
                    previous.value,
                    EcdsaSighashType::All,
                )
                .unwrap();
            let signature = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(
                &Message::from_digest(hash.to_byte_array()),
                &key.private_key,
            ));
            (
                index,
                SignPsbtYieldedObject::Partial(PartialSignature::Sig(
                    bitcoin::PublicKey::new(key.private_key.public_key(&secp)),
                    signature,
                )),
            )
        })
        .collect()
}

#[test]
fn bitcoin_transaction_verifies_signatures_and_assembles_witness() {
    let (account, request, private) = fixture();
    let prepared = BitcoinTransaction::new(&request, &account).unwrap();
    assert_eq!(prepared.psbt.inputs[0].bip32_derivation.len(), 1);
    assert_eq!(prepared.psbt.outputs[0].bip32_derivation.len(), 1);
    let signatures = signatures(&prepared, &private);
    let result = prepared.finish(signatures).unwrap();
    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&result.serialized_transaction).unwrap();
    assert_eq!(transaction.input[0].witness.len(), 2);
    assert_eq!(
        transaction.compute_txid().to_string(),
        result.transaction_id
    );
    assert_eq!(transaction.output[0].value.to_sat(), 9000);
}

#[test]
fn bitcoin_rejects_forged_prevouts_fees_paths_and_unsupported_metadata() {
    let (account, request, _) = fixture();
    for mutation in 0..11 {
        let mut request = request.clone();
        match mutation {
            0 => request.inputs[0].amount += 1,
            1 => request.ref_txs[0].bin_outputs[0].amount += 1,
            2 => request.inputs[0].path[4] += 1,
            3 => request.outputs[0].amount = 10001,
            4 => request.outputs[0].path.as_mut_slice()[3] = 0,
            5 => request.inputs.push(request.inputs[0].clone()),
            6 => request.ref_txs.clear(),
            7 => request.inputs[0].path[0] = 0x8000_0056,
            8 => request.inputs[0].witness = Some(vec![]),
            9 => request.outputs[0].payment_req_index = Some(0),
            _ => request.chunkify = true,
        }
        assert!(
            BitcoinTransaction::new(&request, &account).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn bitcoin_rejects_changed_transactions_missing_duplicate_and_wrong_key_signatures() {
    let (account, request, private) = fixture();
    for mutation in 0..6 {
        let mut prepared = BitcoinTransaction::new(&request, &account).unwrap();
        let mut signatures = signatures(&prepared, &private);
        match mutation {
            0 => prepared.psbt.unsigned_tx.output[0].value = bitcoin::Amount::from_sat(1),
            1 => signatures.clear(),
            2 => signatures.push(signatures[0].clone()),
            3 => signatures[0].0 = 10,
            4 => {
                let other = Xpriv::new_master(Network::Bitcoin, &[2; 32]).unwrap();
                signatures = self::signatures(&prepared, &other);
            }
            _ => {
                if let SignPsbtYieldedObject::Partial(PartialSignature::Sig(_, signature)) =
                    &mut signatures[0].1
                {
                    signature.sighash_type = EcdsaSighashType::None;
                }
            }
        }
        let error = prepared
            .finish(signatures)
            .err()
            .expect("invalid signature must fail");
        assert_eq!(
            error.kind(),
            crate::WalletErrorKind::Device,
            "mutation {mutation}"
        );
    }
}

fn app() -> Vec<u8> {
    Mock::app_info("Bitcoin", "2.4.0")
}
fn ok(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.extend([0x90, 0]);
    bytes
}

#[tokio::test]
async fn bitcoin_message_recovery_binds_key_payload_and_bip137_address_type() {
    let (account, request, private) = fixture();
    let message = b"hw-core Bitcoin test";
    let secp = Secp256k1::new();
    let key = private
        .derive_priv(&secp, &BitcoinAccount::derivation(&[0, 0]))
        .unwrap();
    let hash = bitcoin::sign_message::signed_msg_hash(std::str::from_utf8(message).unwrap());
    let (recovery, compact) = secp
        .sign_ecdsa_recoverable(
            &Message::from_digest(hash.to_byte_array()),
            &key.private_key,
        )
        .serialize_compact();
    let mut signature = vec![31 + recovery.to_i32() as u8];
    signature.extend(compact);
    for tamper in [false, true] {
        let transport = Mock {
            commands: vec![],
            responses: vec![
                app(),
                ok(account.fingerprint.as_bytes().to_vec()),
                app(),
                ok(account.xpub.to_string().into_bytes()),
                app(),
                ok(signature.clone()),
            ]
            .into(),
        };
        let mut client = LedgerClient::new(transport);
        let request = SignMessageRequest::bitcoin(
            request.inputs[0].path.clone(),
            if tamper {
                b"tampered".to_vec()
            } else {
                message.to_vec()
            },
        );
        let result = client.sign_verified_bitcoin_message(&request).await;
        if tamper {
            assert!(result.is_err());
        } else {
            let result = result.unwrap();
            assert_eq!(
                result.address,
                account.address(&request.path).unwrap().to_string()
            );
            assert_eq!(result.signature[0], 39 + recovery.to_i32() as u8);
        }
    }
}

#[tokio::test]
async fn bitcoin_invalid_paths_and_taproot_messages_do_not_contact_device() {
    for path in [
        vec![],
        vec![84, 0, 0, 0, 0],
        vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 2, 0],
        vec![0x8000_0056, 0x8000_0000, 0x8000_0000, 0, 0],
    ] {
        let mut client = LedgerClient::new(Mock {
            commands: vec![],
            responses: VecDeque::new(),
        });
        assert!(
            client
                .sign_verified_bitcoin_message(&SignMessageRequest::bitcoin(path, b"test".to_vec()))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn bitcoin_psbt_yield_is_verified_through_the_public_wallet_api() {
    let (account, request, private) = fixture();
    let prepared = BitcoinTransaction::new(&request, &account).unwrap();
    let mut signatures = signatures(&prepared, &private);
    let (_, SignPsbtYieldedObject::Partial(PartialSignature::Sig(key, signature))) =
        signatures.remove(0)
    else {
        panic!("expected ECDSA signature");
    };
    // YIELD: input index as CompactSize, augmented public-key length, public key and DER+sighash.
    let mut yielded = vec![0x10, 0, 33];
    yielded.extend(key.to_bytes());
    yielded.extend(signature.to_vec());
    yielded.extend([0xe0, 0]);
    let mut client = LedgerClient::new(Mock {
        commands: vec![],
        responses: vec![
            app(),
            ok(account.fingerprint.as_bytes().to_vec()),
            app(),
            ok(account.xpub.to_string().into_bytes()),
            app(),
            yielded,
            ok(vec![]),
        ]
        .into(),
    });
    let result = client.sign_tx(&request.into()).await.unwrap();
    let trezor_connect::thp::SignTxResponse::Bitcoin {
        signatures,
        last_signature,
    } = result
    else {
        panic!("expected shared Bitcoin response");
    };
    let expected = signature.signature.serialize_der().to_vec();
    assert_eq!(signatures, vec![expected.clone()]);
    assert_eq!(last_signature, expected);
}

#[tokio::test]
async fn bitcoin_address_verification_rejects_a_different_account_address() {
    let (account, request, _) = fixture();
    for tamper in [false, true] {
        let mut path = request.inputs[0].path.clone();
        if tamper {
            path[4] += 1;
        }
        let response = account.address(&path).unwrap().to_string();
        let mut client = LedgerClient::new(Mock {
            commands: vec![],
            responses: vec![
                app(),
                ok(account.fingerprint.as_bytes().to_vec()),
                app(),
                ok(account.xpub.to_string().into_bytes()),
                app(),
                ok(response.into_bytes()),
            ]
            .into(),
        });
        let result = client.bitcoin_address(&request.inputs[0].path, false).await;
        assert_eq!(result.is_err(), tamper);
    }
}

#[test]
fn bitcoin_multiple_inputs_preserve_indices_when_device_yields_out_of_order() {
    let (account, mut request, private) = fixture();
    let prepared = BitcoinTransaction::new(&request, &account).unwrap();
    let mut reference = prepared.psbt.inputs[0].non_witness_utxo.clone().unwrap();
    reference.output.push(reference.output[0].clone());
    let hash = hex::decode(reference.compute_txid().to_string()).unwrap();
    request.ref_txs[0].hash = hash.clone();
    let output = request.ref_txs[0].bin_outputs[0].clone();
    request.ref_txs[0].bin_outputs.push(output);
    request.inputs[0].prev_hash = hash;
    let mut second = request.inputs[0].clone();
    second.prev_index = 1;
    request.inputs.push(second);
    let prepared = BitcoinTransaction::new(&request, &account).unwrap();
    let signatures = signatures(&prepared, &private);
    let mut reversed = signatures.clone();
    reversed.reverse();
    let result = prepared.finish(reversed).unwrap();
    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&result.serialized_transaction).unwrap();
    for (index, object) in &signatures {
        let SignPsbtYieldedObject::Partial(PartialSignature::Sig(_, signature)) = object else {
            panic!("ECDSA")
        };
        assert_eq!(
            transaction.input[*index].witness.iter().next().unwrap(),
            signature.to_vec()
        );
        assert_eq!(
            result.signatures[*index],
            signature.signature.serialize_der().to_vec()
        );
    }
    // Same key at both indices: swapping labels must fail the transaction hash check.
    let swapped = signatures
        .into_iter()
        .map(|(index, signature)| (1 - index, signature))
        .collect();
    assert!(
        BitcoinTransaction::new(&request, &account)
            .unwrap()
            .finish(swapped)
            .is_err()
    );
}

#[tokio::test]
async fn bitcoin_taproot_message_is_unsupported_before_device_io() {
    let mut client = LedgerClient::new(Mock::default());
    let request = SignMessageRequest::bitcoin(
        vec![
            86 | crate::bip32::HARDENED,
            crate::bip32::HARDENED,
            crate::bip32::HARDENED,
            0,
            0,
        ],
        b"test".to_vec(),
    );
    assert!(matches!(
        client.sign_verified_bitcoin_message(&request).await,
        Err(crate::WalletError::Unsupported(_))
    ));
    assert!(client.into_transport().commands.is_empty());
}
