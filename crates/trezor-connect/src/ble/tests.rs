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
        }],
        outputs: vec![crate::thp::types::BtcSignOutput {
            address: Some("bc1qtest".to_string()),
            path: Vec::new(),
            amount: 900,
            script_type: crate::thp::types::BtcOutputScriptType::PayToAddress,
            op_return_data: None,
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
        chunkify: false,
    }
}

#[test]
fn handles_prev_meta_request() {
    let btc = sample_btc_sign_tx();
    let ref_txs_by_hash = build_ref_txs_index(&btc);
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

    let result = handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &tx_request).unwrap();
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

    let err = match handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &tx_request) {
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

    let err = match handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &tx_request) {
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
