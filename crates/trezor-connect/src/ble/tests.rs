use super::*;

fn sample_btc_sign_tx() -> crate::thp::types::BtcSignTx {
    crate::thp::types::BtcSignTx {
        version: 2,
        lock_time: 0,
        inputs: vec![crate::thp::types::BtcSignInput {
            path: vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
            prev_hash: vec![0x11; 32],
            prev_index: 0,
            amount: 1000,
            sequence: 0xffff_ffff,
            script_type: crate::thp::types::BtcInputScriptType::SpendWitness,
            script_sig: None,
            witness: None,
            orig_hash: Some(vec![0x33; 32]),
            orig_index: Some(0),
        }],
        outputs: vec![crate::thp::types::BtcSignOutput {
            address: Some("bc1qtest".to_string()),
            path: Vec::new(),
            amount: 900,
            script_type: crate::thp::types::BtcOutputScriptType::PayToAddress,
            op_return_data: None,
            orig_hash: Some(vec![0x33; 32]),
            orig_index: Some(0),
            payment_req_index: Some(0),
        }],
        ref_txs: vec![crate::thp::types::BtcRefTx {
            hash: vec![0x11; 32],
            version: 2,
            lock_time: 0,
            inputs: vec![crate::thp::types::BtcRefTxInput {
                prev_hash: vec![0x22; 32],
                prev_index: 0,
                script_sig: vec![0xaa],
                sequence: 0xffff_fffe,
            }],
            bin_outputs: vec![crate::thp::types::BtcRefTxOutput {
                amount: 1000,
                script_pubkey: vec![0x51],
            }],
            extra_data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            timestamp: None,
            version_group_id: None,
            expiry: None,
            branch_id: None,
        }],
        orig_txs: vec![crate::thp::types::BtcOrigTx {
            hash: vec![0x33; 32],
            version: 2,
            lock_time: 0,
            inputs: vec![crate::thp::types::BtcSignInput {
                path: vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
                prev_hash: vec![0x44; 32],
                prev_index: 0,
                amount: 1000,
                sequence: 0xffff_fffe,
                script_type: crate::thp::types::BtcInputScriptType::SpendWitness,
                script_sig: Some(vec![0xaa]),
                witness: Some(vec![0xbb]),
                orig_hash: None,
                orig_index: None,
            }],
            outputs: vec![crate::thp::types::BtcSignOutput {
                address: Some("bc1qorig".to_string()),
                path: Vec::new(),
                amount: 900,
                script_type: crate::thp::types::BtcOutputScriptType::PayToAddress,
                op_return_data: None,
                orig_hash: None,
                orig_index: None,
                payment_req_index: None,
            }],
            extra_data: None,
            timestamp: None,
            version_group_id: None,
            expiry: None,
            branch_id: None,
        }],
        payment_reqs: Vec::new(),
        chunkify: false,
    }
}

#[test]
fn handles_prev_meta_request() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxMeta),
        request_index: None,
        tx_hash: Some(vec![0x11; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let result =
        handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request).unwrap();
    let BitcoinTxRequestHandling::Ack(ack) = result else {
        panic!("expected ack");
    };
    assert_eq!(
        ack.message_type,
        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK
    );
}

#[test]
fn prev_input_unknown_hash_is_error() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxInput),
        request_index: Some(0),
        tx_hash: Some(vec![0x99; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let err =
        match handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request) {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
    assert!(
        err.to_string()
            .contains("TxInput request references unknown previous transaction hash")
    );
}

#[test]
fn prev_output_out_of_bounds_is_error() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxOutput),
        request_index: Some(2),
        tx_hash: Some(vec![0x11; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let err =
        match handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request) {
            Ok(_) => panic!("expected error"),
            Err(err) => err,
        };
    assert!(
        err.to_string()
            .contains("TxOutput request index 2 out of bounds for previous transaction")
    );
}

#[test]
fn thp_v2_chunk_reassembly_roundtrip() {
    let frame = wire::encode_create_channel_request(&rand::random::<u64>().to_be_bytes());
    let chunks = chunk_v2_frame(&frame, 12);
    assert!(chunks.len() > 1, "expected multi-chunk frame for test");

    let mut pending = None;
    let mut reassembled = None;
    for chunk in chunks {
        if let Some(full) = ingest_thp_v2_chunk(&mut pending, &chunk) {
            reassembled = Some(full);
        }
    }

    assert!(pending.is_none(), "reassembly should complete");
    assert_eq!(reassembled.as_deref(), Some(frame.as_slice()));
}

#[test]
fn handles_tx_orig_input_request() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxOrigInput),
        request_index: Some(0),
        tx_hash: Some(vec![0x33; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let result =
        handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request).unwrap();
    let BitcoinTxRequestHandling::Ack(ack) = result else {
        panic!("expected ack");
    };
    assert_eq!(
        ack.message_type,
        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK
    );
}

#[test]
fn handles_tx_orig_output_request() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxOrigOutput),
        request_index: Some(0),
        tx_hash: Some(vec![0x33; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let result =
        handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request).unwrap();
    let BitcoinTxRequestHandling::Ack(ack) = result else {
        panic!("expected ack");
    };
    assert_eq!(
        ack.message_type,
        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK
    );
}

#[test]
fn tx_orig_input_out_of_bounds_is_error() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxOrigInput),
        request_index: Some(99),
        tx_hash: Some(vec![0x33; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let err = handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("TxOrigInput request index 99 out of bounds"),
        "unexpected error: {err}"
    );
}

#[test]
fn tx_orig_output_out_of_bounds_is_error() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxOrigOutput),
        request_index: Some(99),
        tx_hash: Some(vec![0x33; 32]),
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let err = handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("TxOrigOutput request index 99 out of bounds"),
        "unexpected error: {err}"
    );
}

#[test]
fn handles_tx_payment_req_request() {
    use crate::thp::types::{BtcPaymentRequest, BtcPaymentRequestAmount, BtcPaymentRequestMemo};

    let mut btc = sample_btc_sign_tx();
    btc.payment_reqs = vec![BtcPaymentRequest {
        nonce: Some(vec![0x01, 0x02, 0x03]),
        recipient_name: "Test Merchant".to_string(),
        memos: vec![
            BtcPaymentRequestMemo::Text {
                text: "Invoice #42".to_string(),
            },
            BtcPaymentRequestMemo::TextDetails {
                title: "Details".to_string(),
                text: "Extra context".to_string(),
            },
            BtcPaymentRequestMemo::Refund {
                address: "tb1qrefund".to_string(),
                path: vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 0],
                mac: vec![0xaa, 0xbb],
            },
            BtcPaymentRequestMemo::CoinPurchase {
                coin_type: 1,
                amount: "0.025 BTC".to_string(),
                address: "tb1qcoinpurchase".to_string(),
                path: vec![0x8000_0001, 0x8000_0000, 0x8000_0000, 1, 1],
                mac: vec![0xcc, 0xdd],
            },
        ],
        amount: Some(BtcPaymentRequestAmount::from_sats(900)),
        signature: vec![0xde, 0xad],
    }];

    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxPaymentReq),
        request_index: Some(0),
        tx_hash: None,
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let result =
        handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request).unwrap();
    let BitcoinTxRequestHandling::Ack(ack) = result else {
        panic!("expected ack");
    };
    assert_eq!(
        ack.message_type,
        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK_PAYMENT_REQUEST
    );
}

#[test]
fn tx_payment_req_missing_entry_is_error() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);
    let tx_request = DecodedBitcoinTxRequest {
        request_type: Some(BitcoinTxRequestType::TxPaymentReq),
        request_index: Some(0),
        tx_hash: None,
        extra_data_len: None,
        extra_data_offset: None,
        signature_index: None,
        signature: None,
        serialized_tx: None,
    };

    let err = handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("TxPaymentReq request index 0 out of bounds"),
        "unexpected error: {err}"
    );
}

#[test]
fn thp_v2_chunk_reassembly_recovers_after_bad_continuation() {
    let frame1 = wire::encode_create_channel_request(&rand::random::<u64>().to_be_bytes());
    let chunks1 = chunk_v2_frame(&frame1, 12);
    assert!(chunks1.len() > 1, "expected multi-chunk frame for test");

    let frame2 = wire::encode_create_channel_request(&rand::random::<u64>().to_be_bytes());
    let chunks2 = chunk_v2_frame(&frame2, 12);
    assert!(chunks2.len() > 1, "expected multi-chunk frame for test");

    let mut pending = None;
    assert!(ingest_thp_v2_chunk(&mut pending, &chunks1[0]).is_none());
    assert!(pending.is_some(), "first chunk should start pending state");

    let mut bad = chunks1[1].clone();
    bad[1] ^= 0x01; // break channel bytes in continuation header
    assert!(ingest_thp_v2_chunk(&mut pending, &bad).is_none());

    let mut reassembled = None;
    for chunk in chunks2 {
        if let Some(full) = ingest_thp_v2_chunk(&mut pending, &chunk) {
            reassembled = Some(full);
        }
    }

    assert!(pending.is_none(), "reassembly should complete");
    assert_eq!(reassembled.as_deref(), Some(frame2.as_slice()));
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.is_empty() {
        return Vec::new();
    }
    hex::decode(stripped).expect("invalid hex in fixture")
}

fn load_rbf_fixture() -> crate::thp::types::BtcSignTx {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/data/bitcoin/btc_rbf_with_payment_req.json"
    ))
    .expect("fixture is valid JSON");

    let parse_path = |s: &str| -> Vec<u32> {
        s.strip_prefix("m/")
            .unwrap_or(s)
            .split('/')
            .map(|component| {
                if let Some(stripped) = component.strip_suffix('\'') {
                    stripped.parse::<u32>().unwrap() | 0x8000_0000
                } else {
                    component.parse::<u32>().unwrap()
                }
            })
            .collect()
    };

    let inputs: Vec<crate::thp::types::BtcSignInput> = json["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|inp| crate::thp::types::BtcSignInput {
            path: parse_path(inp["path"].as_str().unwrap()),
            prev_hash: hex_to_bytes(inp["prev_hash"].as_str().unwrap()),
            prev_index: inp["prev_index"].as_u64().unwrap() as u32,
            amount: inp["amount"].as_str().unwrap().parse().unwrap(),
            sequence: inp["sequence"].as_u64().unwrap_or(0xffff_ffff) as u32,
            script_type: match inp["script_type"].as_str().unwrap_or("spendwitness") {
                "spendwitness" => crate::thp::types::BtcInputScriptType::SpendWitness,
                "spendaddress" => crate::thp::types::BtcInputScriptType::SpendAddress,
                "spendtaproot" => crate::thp::types::BtcInputScriptType::SpendTaproot,
                other => panic!("unsupported script_type: {other}"),
            },
            script_sig: inp["script_sig"].as_str().map(hex_to_bytes),
            witness: inp["witness"].as_str().map(hex_to_bytes),
            orig_hash: inp["orig_hash"].as_str().map(hex_to_bytes),
            orig_index: inp["orig_index"].as_u64().map(|index| index as u32),
        })
        .collect();

    let outputs: Vec<crate::thp::types::BtcSignOutput> = json["outputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|out| crate::thp::types::BtcSignOutput {
            address: out["address"].as_str().map(String::from),
            path: out["path"].as_str().map(parse_path).unwrap_or_default(),
            amount: out["amount"].as_str().unwrap().parse().unwrap(),
            script_type: match out["script_type"].as_str().unwrap_or("paytoaddress") {
                "paytowitness" => crate::thp::types::BtcOutputScriptType::PayToWitness,
                "paytoaddress" => crate::thp::types::BtcOutputScriptType::PayToAddress,
                "paytotaproot" => crate::thp::types::BtcOutputScriptType::PayToTaproot,
                other => panic!("unsupported output script_type: {other}"),
            },
            op_return_data: None,
            orig_hash: out["orig_hash"].as_str().map(hex_to_bytes),
            orig_index: out["orig_index"].as_u64().map(|index| index as u32),
            payment_req_index: out["payment_req_index"].as_u64().map(|index| index as u32),
        })
        .collect();

    let ref_txs: Vec<crate::thp::types::BtcRefTx> = json["ref_txs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rtx| crate::thp::types::BtcRefTx {
            hash: hex_to_bytes(rtx["hash"].as_str().unwrap()),
            version: rtx["version"].as_u64().unwrap() as u32,
            lock_time: rtx["lock_time"].as_u64().unwrap() as u32,
            inputs: rtx["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|ri| crate::thp::types::BtcRefTxInput {
                    prev_hash: hex_to_bytes(ri["prev_hash"].as_str().unwrap()),
                    prev_index: ri["prev_index"].as_u64().unwrap() as u32,
                    script_sig: hex_to_bytes(ri["script_sig"].as_str().unwrap()),
                    sequence: ri["sequence"].as_u64().unwrap_or(0xffff_ffff) as u32,
                })
                .collect(),
            bin_outputs: rtx["bin_outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|bo| crate::thp::types::BtcRefTxOutput {
                    amount: bo["amount"].as_str().unwrap().parse().unwrap(),
                    script_pubkey: hex_to_bytes(bo["script_pubkey"].as_str().unwrap()),
                })
                .collect(),
            extra_data: None,
            timestamp: None,
            version_group_id: None,
            expiry: None,
            branch_id: None,
        })
        .collect();

    let orig_txs: Vec<crate::thp::types::BtcOrigTx> = json["orig_txs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|otx| crate::thp::types::BtcOrigTx {
            hash: hex_to_bytes(otx["hash"].as_str().unwrap()),
            version: otx["version"].as_u64().unwrap() as u32,
            lock_time: otx["lock_time"].as_u64().unwrap() as u32,
            inputs: otx["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|inp| crate::thp::types::BtcSignInput {
                    path: parse_path(inp["path"].as_str().unwrap()),
                    prev_hash: hex_to_bytes(inp["prev_hash"].as_str().unwrap()),
                    prev_index: inp["prev_index"].as_u64().unwrap() as u32,
                    amount: inp["amount"].as_str().unwrap().parse().unwrap(),
                    sequence: inp["sequence"].as_u64().unwrap_or(0xffff_ffff) as u32,
                    script_type: match inp["script_type"].as_str().unwrap_or("spendwitness") {
                        "spendwitness" => crate::thp::types::BtcInputScriptType::SpendWitness,
                        "spendaddress" => crate::thp::types::BtcInputScriptType::SpendAddress,
                        "spendtaproot" => crate::thp::types::BtcInputScriptType::SpendTaproot,
                        other => panic!("unsupported script_type: {other}"),
                    },
                    script_sig: inp["script_sig"].as_str().map(hex_to_bytes),
                    witness: inp["witness"].as_str().map(hex_to_bytes),
                    orig_hash: inp["orig_hash"].as_str().map(hex_to_bytes),
                    orig_index: inp["orig_index"].as_u64().map(|index| index as u32),
                })
                .collect(),
            outputs: otx["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|out| crate::thp::types::BtcSignOutput {
                    address: out["address"].as_str().map(String::from),
                    path: out["path"].as_str().map(parse_path).unwrap_or_default(),
                    amount: out["amount"].as_str().unwrap().parse().unwrap(),
                    script_type: match out["script_type"].as_str().unwrap_or("paytoaddress") {
                        "paytowitness" => crate::thp::types::BtcOutputScriptType::PayToWitness,
                        "paytoaddress" => crate::thp::types::BtcOutputScriptType::PayToAddress,
                        "paytotaproot" => crate::thp::types::BtcOutputScriptType::PayToTaproot,
                        other => panic!("unsupported output script_type: {other}"),
                    },
                    op_return_data: out["op_return_data"].as_str().map(hex_to_bytes),
                    orig_hash: out["orig_hash"].as_str().map(hex_to_bytes),
                    orig_index: out["orig_index"].as_u64().map(|index| index as u32),
                    payment_req_index: out["payment_req_index"].as_u64().map(|index| index as u32),
                })
                .collect(),
            extra_data: otx["extra_data"].as_str().map(hex_to_bytes),
            timestamp: otx["timestamp"].as_u64().map(|value| value as u32),
            version_group_id: otx["version_group_id"].as_u64().map(|value| value as u32),
            expiry: otx["expiry"].as_u64().map(|value| value as u32),
            branch_id: otx["branch_id"].as_u64().map(|value| value as u32),
        })
        .collect();

    let payment_reqs: Vec<crate::thp::types::BtcPaymentRequest> = json["payment_reqs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pr| crate::thp::types::BtcPaymentRequest {
            nonce: pr["nonce"].as_str().map(hex_to_bytes),
            recipient_name: pr["recipient_name"].as_str().unwrap().to_string(),
            memos: pr["memos"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| match m["type"].as_str().unwrap() {
                    "text" => crate::thp::types::BtcPaymentRequestMemo::Text {
                        text: m["text"].as_str().unwrap().to_string(),
                    },
                    "text_details" => crate::thp::types::BtcPaymentRequestMemo::TextDetails {
                        title: m["title"].as_str().unwrap().to_string(),
                        text: m["text"].as_str().unwrap().to_string(),
                    },
                    "refund" => crate::thp::types::BtcPaymentRequestMemo::Refund {
                        address: m["address"].as_str().unwrap().to_string(),
                        path: parse_path(m["path"].as_str().unwrap()),
                        mac: hex_to_bytes(m["mac"].as_str().unwrap()),
                    },
                    "coin_purchase" => crate::thp::types::BtcPaymentRequestMemo::CoinPurchase {
                        coin_type: m["coin_type"].as_u64().unwrap() as u32,
                        amount: m["amount"].as_str().unwrap().to_string(),
                        address: m["address"].as_str().unwrap().to_string(),
                        path: parse_path(m["path"].as_str().unwrap()),
                        mac: hex_to_bytes(m["mac"].as_str().unwrap()),
                    },
                    other => panic!("unsupported memo type: {other}"),
                })
                .collect(),
            amount: pr["amount"].as_str().map(|s| {
                crate::thp::types::BtcPaymentRequestAmount::from_sats(s.parse::<u64>().unwrap())
            }),
            signature: hex_to_bytes(pr["signature"].as_str().unwrap()),
        })
        .collect();

    crate::thp::types::BtcSignTx {
        version: json["version"].as_u64().unwrap() as u32,
        lock_time: json["lock_time"].as_u64().unwrap() as u32,
        inputs,
        outputs,
        ref_txs,
        orig_txs,
        payment_reqs,
        chunkify: false,
    }
}

#[test]
fn rbf_fee_bump_fixture_full_request_sequence() {
    let btc = load_rbf_fixture();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
    let orig_txs_by_hash = build_orig_txs_index(&btc);

    assert_eq!(btc.inputs.len(), 2);
    assert_eq!(btc.outputs.len(), 2);
    assert_eq!(btc.ref_txs.len(), 2);
    assert_eq!(btc.orig_txs.len(), 1);
    assert_eq!(btc.payment_reqs.len(), 1);
    assert_eq!(btc.payment_reqs[0].recipient_name, "Acme Coffee Co.");

    let fixture_json: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/data/bitcoin/btc_rbf_with_payment_req.json"
    ))
    .unwrap();
    let sequence = fixture_json["firmware_request_sequence"]
        .as_array()
        .unwrap();

    let mut ack_count = 0u32;
    let mut finished = false;

    for (step, entry) in sequence.iter().enumerate() {
        let req_type_str = entry["type"].as_str().unwrap();

        let request_type = match req_type_str {
            "TXINPUT" => Some(BitcoinTxRequestType::TxInput),
            "TXOUTPUT" => Some(BitcoinTxRequestType::TxOutput),
            "TXMETA" => Some(BitcoinTxRequestType::TxMeta),
            "TXORIGINPUT" => Some(BitcoinTxRequestType::TxOrigInput),
            "TXORIGOUTPUT" => Some(BitcoinTxRequestType::TxOrigOutput),
            "TXPAYMENTREQ" => Some(BitcoinTxRequestType::TxPaymentReq),
            "TXFINISHED" => Some(BitcoinTxRequestType::TxFinished),
            other => panic!("unknown request type in fixture step {step}: {other}"),
        };

        let tx_hash = entry["tx_hash"].as_str().map(hex_to_bytes);

        let tx_request = DecodedBitcoinTxRequest {
            request_type,
            request_index: entry["index"].as_u64().map(|v| v as u32),
            tx_hash,
            extra_data_len: None,
            extra_data_offset: None,
            signature_index: None,
            signature: None,
            serialized_tx: None,
        };

        let result =
            handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request)
                .unwrap_or_else(|e| panic!("step {step} ({req_type_str}): unexpected error: {e}"));

        match result {
            BitcoinTxRequestHandling::Ack(ack) => {
                if req_type_str == "TXPAYMENTREQ" {
                    assert_eq!(
                        ack.message_type,
                        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK_PAYMENT_REQUEST,
                        "step {step}: TXPAYMENTREQ should produce payment-request ack"
                    );
                } else {
                    assert_eq!(
                        ack.message_type,
                        crate::thp::proto::MESSAGE_TYPE_BITCOIN_TX_ACK,
                        "step {step} ({req_type_str}): expected standard tx ack"
                    );
                }
                ack_count += 1;
            }
            BitcoinTxRequestHandling::Finished => {
                assert_eq!(req_type_str, "TXFINISHED", "step {step}: unexpected finish");
                finished = true;
            }
            BitcoinTxRequestHandling::Continue => {
                panic!("step {step} ({req_type_str}): unexpected Continue");
            }
        }
    }

    assert!(finished, "sequence must end with TXFINISHED");
    assert_eq!(ack_count, 14, "expected 14 ack responses in the sequence");
}
