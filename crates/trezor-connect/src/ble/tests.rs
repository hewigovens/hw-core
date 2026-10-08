use super::bitcoin::*;
use super::*;
use crate::thp::proto::{
    BitcoinTxAck, BitcoinTxAckPaymentRequest, BitcoinTxRequestType, DecodedBitcoinTxRequest,
    MESSAGE_TYPE_SUCCESS, TxAck, WireMessage,
};
use serde::Deserialize;

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
            multisig: None,
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
            multisig: None,
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
                multisig: None,
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
                multisig: None,
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
    assert_eq!(ack.message_type, BitcoinTxAck::MESSAGE_TYPE);
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
    assert_eq!(ack.message_type, BitcoinTxAck::MESSAGE_TYPE);
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
    assert_eq!(ack.message_type, BitcoinTxAck::MESSAGE_TYPE);
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
    assert_eq!(ack.message_type, BitcoinTxAckPaymentRequest::MESSAGE_TYPE);
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
fn thp_transport_error_codes_map_to_spec_meanings() {
    assert!(matches!(
        backend_error_from_transport(TransportError::TransportBusy),
        BackendError::TransportBusy
    ));
    assert!(matches!(
        backend_error_from_transport(TransportError::DeviceLocked),
        BackendError::DeviceLocked
    ));
    assert!(matches!(
        backend_error_from_transport(TransportError::DecryptionFailed),
        BackendError::DeviceError { code: 3, .. }
    ));
}

#[test]
fn failure_codes_map_to_protobuf_meanings() {
    let failure = |code: i32| {
        let mut payload = Vec::new();
        FailureProto {
            code: Some(code),
            message: None,
        }
        .encode(&mut payload)
        .expect("encode failure");
        decode_failure_as_backend_error(&payload)
    };

    assert!(matches!(failure(5), BackendError::PinExpected));
    assert!(matches!(failure(15), BackendError::DeviceBusy));
    assert!(matches!(failure(99), BackendError::DeviceFirmwareError));
    assert!(matches!(
        failure(5 + 256),
        BackendError::DeviceError { code: 261, .. }
    ));
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.is_empty() {
        return Vec::new();
    }
    hex::decode(stripped).expect("invalid hex in fixture")
}

fn default_sequence() -> u32 {
    0xffff_ffff
}

fn default_input_script_type() -> String {
    "spendwitness".to_string()
}

fn default_output_script_type() -> String {
    "paytoaddress".to_string()
}

fn parse_path(path: &str) -> Vec<u32> {
    path.strip_prefix("m/")
        .unwrap_or(path)
        .split('/')
        .map(|component| {
            if let Some(stripped) = component.strip_suffix('\'') {
                stripped.parse::<u32>().unwrap() | 0x8000_0000
            } else {
                component.parse::<u32>().unwrap()
            }
        })
        .collect()
}

fn parse_input_script_type(value: &str) -> crate::thp::types::BtcInputScriptType {
    match value {
        "spendwitness" => crate::thp::types::BtcInputScriptType::SpendWitness,
        "spendaddress" => crate::thp::types::BtcInputScriptType::SpendAddress,
        "spendtaproot" => crate::thp::types::BtcInputScriptType::SpendTaproot,
        other => panic!("unsupported script_type: {other}"),
    }
}

fn parse_output_script_type(value: &str) -> crate::thp::types::BtcOutputScriptType {
    match value {
        "paytowitness" => crate::thp::types::BtcOutputScriptType::PayToWitness,
        "paytoaddress" => crate::thp::types::BtcOutputScriptType::PayToAddress,
        "paytotaproot" => crate::thp::types::BtcOutputScriptType::PayToTaproot,
        other => panic!("unsupported output script_type: {other}"),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct BtcFixture {
    version: u32,
    #[serde(default)]
    lock_time: u32,
    #[serde(default)]
    inputs: Vec<FixtureSignInput>,
    #[serde(default)]
    outputs: Vec<FixtureSignOutput>,
    #[serde(default)]
    ref_txs: Vec<FixtureRefTx>,
    #[serde(default)]
    orig_txs: Vec<FixtureOrigTx>,
    #[serde(default)]
    payment_reqs: Vec<FixturePaymentRequest>,
    #[serde(default)]
    firmware_request_sequence: Vec<FixtureTxRequestStep>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureSignInput {
    path: String,
    prev_hash: String,
    prev_index: u32,
    amount: String,
    #[serde(default = "default_sequence")]
    sequence: u32,
    #[serde(default = "default_input_script_type")]
    script_type: String,
    #[serde(default)]
    script_sig: Option<String>,
    #[serde(default)]
    witness: Option<String>,
    #[serde(default)]
    orig_hash: Option<String>,
    #[serde(default)]
    orig_index: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureSignOutput {
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    path: Option<String>,
    amount: String,
    #[serde(default = "default_output_script_type")]
    script_type: String,
    #[serde(default)]
    op_return_data: Option<String>,
    #[serde(default)]
    orig_hash: Option<String>,
    #[serde(default)]
    orig_index: Option<u32>,
    #[serde(default)]
    payment_req_index: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureRefTxInput {
    prev_hash: String,
    prev_index: u32,
    script_sig: String,
    #[serde(default = "default_sequence")]
    sequence: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureRefTxOutput {
    amount: String,
    script_pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureRefTx {
    hash: String,
    version: u32,
    lock_time: u32,
    #[serde(default)]
    inputs: Vec<FixtureRefTxInput>,
    #[serde(default)]
    bin_outputs: Vec<FixtureRefTxOutput>,
    #[serde(default)]
    extra_data: Option<String>,
    #[serde(default)]
    timestamp: Option<u32>,
    #[serde(default)]
    version_group_id: Option<u32>,
    #[serde(default)]
    expiry: Option<u32>,
    #[serde(default)]
    branch_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureOrigTx {
    hash: String,
    version: u32,
    lock_time: u32,
    #[serde(default)]
    inputs: Vec<FixtureSignInput>,
    #[serde(default)]
    outputs: Vec<FixtureSignOutput>,
    #[serde(default)]
    extra_data: Option<String>,
    #[serde(default)]
    timestamp: Option<u32>,
    #[serde(default)]
    version_group_id: Option<u32>,
    #[serde(default)]
    expiry: Option<u32>,
    #[serde(default)]
    branch_id: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixturePaymentRequest {
    #[serde(default)]
    nonce: Option<String>,
    recipient_name: String,
    #[serde(default)]
    memos: Vec<FixturePaymentRequestMemo>,
    #[serde(default)]
    amount: Option<String>,
    signature: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FixturePaymentRequestMemo {
    #[serde(rename = "type")]
    memo_type: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    coin_type: Option<u32>,
    #[serde(default)]
    amount: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureTxRequestStep {
    #[serde(rename = "type")]
    request_type: String,
    #[serde(default)]
    index: Option<u32>,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    extra_data_len: Option<u32>,
    #[serde(default)]
    extra_data_offset: Option<u32>,
    #[serde(default)]
    signature_index: Option<u32>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    serialized_tx: Option<String>,
    #[serde(default)]
    expected_extra_data: Option<String>,
}

impl FixtureSignInput {
    fn to_sign_input(&self) -> crate::thp::types::BtcSignInput {
        crate::thp::types::BtcSignInput {
            path: parse_path(&self.path),
            prev_hash: hex_to_bytes(&self.prev_hash),
            prev_index: self.prev_index,
            amount: self.amount.parse().unwrap(),
            sequence: self.sequence,
            script_type: parse_input_script_type(&self.script_type),
            multisig: None,
            script_sig: self.script_sig.as_deref().map(hex_to_bytes),
            witness: self.witness.as_deref().map(hex_to_bytes),
            orig_hash: self.orig_hash.as_deref().map(hex_to_bytes),
            orig_index: self.orig_index,
        }
    }
}

impl FixtureSignOutput {
    fn to_sign_output(&self) -> crate::thp::types::BtcSignOutput {
        crate::thp::types::BtcSignOutput {
            address: self.address.clone(),
            path: self.path.as_deref().map(parse_path).unwrap_or_default(),
            amount: self.amount.parse().unwrap(),
            script_type: parse_output_script_type(&self.script_type),
            multisig: None,
            op_return_data: self.op_return_data.as_deref().map(hex_to_bytes),
            orig_hash: self.orig_hash.as_deref().map(hex_to_bytes),
            orig_index: self.orig_index,
            payment_req_index: self.payment_req_index,
        }
    }
}

impl FixtureRefTx {
    fn to_ref_tx(&self) -> crate::thp::types::BtcRefTx {
        crate::thp::types::BtcRefTx {
            hash: hex_to_bytes(&self.hash),
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(|input| crate::thp::types::BtcRefTxInput {
                    prev_hash: hex_to_bytes(&input.prev_hash),
                    prev_index: input.prev_index,
                    script_sig: hex_to_bytes(&input.script_sig),
                    sequence: input.sequence,
                })
                .collect(),
            bin_outputs: self
                .bin_outputs
                .iter()
                .map(|output| crate::thp::types::BtcRefTxOutput {
                    amount: output.amount.parse().unwrap(),
                    script_pubkey: hex_to_bytes(&output.script_pubkey),
                })
                .collect(),
            extra_data: self.extra_data.as_deref().map(hex_to_bytes),
            timestamp: self.timestamp,
            version_group_id: self.version_group_id,
            expiry: self.expiry,
            branch_id: self.branch_id,
        }
    }
}

impl FixtureOrigTx {
    fn to_orig_tx(&self) -> crate::thp::types::BtcOrigTx {
        crate::thp::types::BtcOrigTx {
            hash: hex_to_bytes(&self.hash),
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(FixtureSignInput::to_sign_input)
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(FixtureSignOutput::to_sign_output)
                .collect(),
            extra_data: self.extra_data.as_deref().map(hex_to_bytes),
            timestamp: self.timestamp,
            version_group_id: self.version_group_id,
            expiry: self.expiry,
            branch_id: self.branch_id,
        }
    }
}

impl FixturePaymentRequestMemo {
    fn to_memo(&self) -> crate::thp::types::BtcPaymentRequestMemo {
        match self.memo_type.as_str() {
            "text" => crate::thp::types::BtcPaymentRequestMemo::Text {
                text: self.text.clone().expect("text memo must include text"),
            },
            "text_details" => crate::thp::types::BtcPaymentRequestMemo::TextDetails {
                title: self
                    .title
                    .clone()
                    .expect("text_details memo must include title"),
                text: self
                    .text
                    .clone()
                    .expect("text_details memo must include text"),
            },
            "refund" => crate::thp::types::BtcPaymentRequestMemo::Refund {
                address: self
                    .address
                    .clone()
                    .expect("refund memo must include address"),
                path: parse_path(self.path.as_deref().expect("refund memo must include path")),
                mac: hex_to_bytes(self.mac.as_deref().expect("refund memo must include mac")),
            },
            "coin_purchase" => crate::thp::types::BtcPaymentRequestMemo::CoinPurchase {
                coin_type: self
                    .coin_type
                    .expect("coin_purchase memo must include coin_type"),
                amount: self
                    .amount
                    .clone()
                    .expect("coin_purchase memo must include amount"),
                address: self
                    .address
                    .clone()
                    .expect("coin_purchase memo must include address"),
                path: parse_path(
                    self.path
                        .as_deref()
                        .expect("coin_purchase memo must include path"),
                ),
                mac: hex_to_bytes(
                    self.mac
                        .as_deref()
                        .expect("coin_purchase memo must include mac"),
                ),
            },
            other => panic!("unsupported memo type: {other}"),
        }
    }
}

impl FixturePaymentRequest {
    fn to_payment_request(&self) -> crate::thp::types::BtcPaymentRequest {
        crate::thp::types::BtcPaymentRequest {
            nonce: self.nonce.as_deref().map(hex_to_bytes),
            recipient_name: self.recipient_name.clone(),
            memos: self
                .memos
                .iter()
                .map(FixturePaymentRequestMemo::to_memo)
                .collect(),
            amount: self.amount.as_deref().map(|amount| {
                crate::thp::types::BtcPaymentRequestAmount::from_sats(
                    amount.parse::<u64>().unwrap(),
                )
            }),
            signature: hex_to_bytes(&self.signature),
        }
    }
}

impl FixtureTxRequestStep {
    fn decoded_request(&self) -> DecodedBitcoinTxRequest {
        let request_type = match self.request_type.as_str() {
            "TXINPUT" => Some(BitcoinTxRequestType::TxInput),
            "TXOUTPUT" => Some(BitcoinTxRequestType::TxOutput),
            "TXMETA" => Some(BitcoinTxRequestType::TxMeta),
            "TXEXTRADATA" => Some(BitcoinTxRequestType::TxExtraData),
            "TXORIGINPUT" => Some(BitcoinTxRequestType::TxOrigInput),
            "TXORIGOUTPUT" => Some(BitcoinTxRequestType::TxOrigOutput),
            "TXPAYMENTREQ" => Some(BitcoinTxRequestType::TxPaymentReq),
            "TXFINISHED" => Some(BitcoinTxRequestType::TxFinished),
            other => panic!("unknown request type in fixture: {other}"),
        };

        DecodedBitcoinTxRequest {
            request_type,
            request_index: self.index,
            tx_hash: self.tx_hash.as_deref().map(hex_to_bytes),
            extra_data_len: self.extra_data_len,
            extra_data_offset: self.extra_data_offset,
            signature_index: self.signature_index,
            signature: self.signature.as_deref().map(hex_to_bytes),
            serialized_tx: self.serialized_tx.as_deref().map(hex_to_bytes),
        }
    }
}

impl BtcFixture {
    fn to_sign_tx(&self) -> crate::thp::types::BtcSignTx {
        crate::thp::types::BtcSignTx {
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(FixtureSignInput::to_sign_input)
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(FixtureSignOutput::to_sign_output)
                .collect(),
            ref_txs: self.ref_txs.iter().map(FixtureRefTx::to_ref_tx).collect(),
            orig_txs: self
                .orig_txs
                .iter()
                .map(FixtureOrigTx::to_orig_tx)
                .collect(),
            payment_reqs: self
                .payment_reqs
                .iter()
                .map(FixturePaymentRequest::to_payment_request)
                .collect(),
            chunkify: false,
        }
    }
}

fn parse_btc_fixture(fixture_json: &str) -> BtcFixture {
    serde_json::from_str(fixture_json).expect("fixture is valid JSON")
}

fn load_rbf_fixture() -> BtcFixture {
    parse_btc_fixture(include_str!(
        "../../../../tests/data/bitcoin/btc_rbf_with_payment_req.json"
    ))
}

fn load_extra_data_fixture() -> BtcFixture {
    parse_btc_fixture(include_str!(
        "../../../../tests/data/bitcoin/btc_ref_tx_with_extra_data_sequence.json"
    ))
}

fn run_fixture_request_sequence(
    btc: &crate::thp::types::BtcSignTx,
    fixture: &BtcFixture,
) -> (u32, Option<Vec<u8>>) {
    let ref_txs_by_hash = build_ref_txs_index(btc);
    let orig_txs_by_hash = build_orig_txs_index(btc);

    let mut ack_count = 0u32;
    let mut finished = false;
    let mut latest_signature = None;

    for (step, entry) in fixture.firmware_request_sequence.iter().enumerate() {
        let req_type_str = entry.request_type.as_str();
        let tx_request = entry.decoded_request();
        if let Some(signature) = tx_request.signature.as_ref() {
            latest_signature = Some(signature.clone());
        }

        let result =
            handle_bitcoin_tx_request(btc, &ref_txs_by_hash, &orig_txs_by_hash, &tx_request)
                .unwrap_or_else(|e| panic!("step {step} ({req_type_str}): unexpected error: {e}"));

        match result {
            BitcoinTxRequestHandling::Ack(ack) => {
                if req_type_str == "TXPAYMENTREQ" {
                    assert_eq!(
                        ack.message_type,
                        BitcoinTxAckPaymentRequest::MESSAGE_TYPE,
                        "step {step}: TXPAYMENTREQ should produce payment-request ack"
                    );
                } else {
                    assert_eq!(
                        ack.message_type,
                        BitcoinTxAck::MESSAGE_TYPE,
                        "step {step} ({req_type_str}): expected standard tx ack"
                    );
                }
                if req_type_str == "TXEXTRADATA" {
                    let expected_chunk = hex_to_bytes(
                        entry
                            .expected_extra_data
                            .as_deref()
                            .expect("TXEXTRADATA fixture must include expected_extra_data"),
                    );
                    let expected = expected_chunk.tx_ack();
                    assert_eq!(
                        ack.payload, expected.payload,
                        "step {step}: TXEXTRADATA ack payload should match requested chunk"
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
    (ack_count, latest_signature)
}

#[test]
fn rbf_fee_bump_fixture_full_request_sequence() {
    let fixture = load_rbf_fixture();
    let btc = fixture.to_sign_tx();

    assert_eq!(btc.inputs.len(), 2);
    assert_eq!(btc.outputs.len(), 2);
    assert_eq!(btc.ref_txs.len(), 2);
    assert_eq!(btc.orig_txs.len(), 1);
    assert_eq!(btc.payment_reqs.len(), 1);
    assert_eq!(btc.payment_reqs[0].recipient_name, "Acme Coffee Co.");

    let (ack_count, latest_signature) = run_fixture_request_sequence(&btc, &fixture);
    assert_eq!(ack_count, 14, "expected 14 ack responses in the sequence");
    assert_eq!(latest_signature, None, "fixture does not emit signatures");
}

#[test]
fn ref_tx_extra_data_fixture_sequence_yields_expected_chunks_and_signature() {
    let fixture = load_extra_data_fixture();
    let btc = fixture.to_sign_tx();

    assert_eq!(btc.inputs.len(), 1);
    assert_eq!(btc.outputs.len(), 1);
    assert_eq!(btc.ref_txs.len(), 1);
    let expected_extra_data = hex_to_bytes("0xdeadbeefcafebabe");
    assert_eq!(
        btc.ref_txs[0].extra_data.as_deref(),
        Some(expected_extra_data.as_slice())
    );

    let (ack_count, latest_signature) = run_fixture_request_sequence(&btc, &fixture);
    assert_eq!(ack_count, 5, "expected 5 ack responses in the sequence");
    assert_eq!(latest_signature, Some(hex_to_bytes("0x3045022100feedface")));
}

#[test]
fn credential_lookup_always_uses_host_key_and_sends_matching_credential() {
    use crate::thp::crypto::Curve25519KeyPair;
    use crate::thp::crypto::curve25519::curve25519;
    use sha2::{Digest, Sha256};

    let mut rng = rand::rng();
    let trezor_static = Curve25519KeyPair::generate(&mut rng);
    let ephemeral = Curve25519KeyPair::generate(&mut rng).public_key;
    let mask: [u8; 32] = Sha256::new()
        .chain_update(trezor_static.public_key)
        .chain_update(ephemeral)
        .finalize()
        .into();
    let masked = curve25519(&mask, &trezor_static.public_key);

    let credentials = SharedCredentials::default();
    {
        let mut inner = credentials.lock();
        inner.static_key = [0x42; 32];
        inner.known = vec![
            KnownCredential {
                credential: "0011".into(),
                trezor_static_public_key: Some(vec![0x99; 32]),
                autoconnect: false,
            },
            KnownCredential {
                credential: "aabb".into(),
                trezor_static_public_key: Some(trezor_static.public_key.to_vec()),
                autoconnect: true,
            },
        ];
    }

    let mut dest = [0u8; 160];
    let found = credentials
        .lookup(&ephemeral, &masked, &mut dest)
        .expect("host key is always supplied");
    assert_eq!(found.local_static_privkey, &[0x42; 32]);
    let payload = messages::ThpHandshakeCompletionReqNoisePayload::decode(found.auth_credential)
        .expect("noise payload");
    assert_eq!(payload.host_pairing_credential, Some(vec![0xaa, 0xbb]));
    assert_eq!(
        credentials
            .lock()
            .selected
            .as_ref()
            .map(|c| c.credential.as_str()),
        Some("aabb")
    );

    let found = credentials
        .lookup(&ephemeral, &[0x01; 32], &mut dest)
        .expect("host key is always supplied");
    assert_eq!(found.local_static_privkey, &[0x42; 32]);
    assert!(found.auth_credential.is_empty());
    assert!(credentials.lock().selected.is_none());
}

mod fake_device {
    use std::collections::VecDeque;

    use trezor_thp::channel::PacketInResult;
    use trezor_thp::channel::buffered::Buffered;
    use trezor_thp::channel::device;
    use trezor_thp::credential::CredentialVerifier;

    use super::super::*;
    use crate::thp::proto::MESSAGE_TYPE_SUCCESS;

    const DEVICE_KEY: [u8; 32] = [0x11; 32];
    // ThpDeviceProperties: protocol 2.0, pairing methods SkipPairing + CodeEntry.
    const DEVICE_PROPERTIES: &[u8] =
        b"\x0a\x04\x54\x33\x57\x31\x10\x00\x18\x02\x20\x00\x28\x01\x28\x02";
    pub const CHANNEL_ID: u16 = 0x1234;

    #[derive(Clone)]
    pub struct AlwaysUnpaired;

    impl CredentialVerifier for AlwaysUnpaired {
        fn verify(&self, _remote_static_pubkey: &[u8], _credential: &[u8]) -> PairingState {
            PairingState::Unpaired
        }
    }

    enum State {
        Mux(Box<Buffered<device::Mux<NoiseBackend>>>),
        Opening(Box<Buffered<device::ChannelOpen<AlwaysUnpaired, NoiseBackend>>>),
        Open(Box<Buffered<device::Channel<NoiseBackend>>>),
    }

    /// In-process device built from trezor-thp's device side, driven synchronously by host packets.
    pub struct FakeDevice {
        state: Option<State>,
        outbox: VecDeque<Vec<u8>>,
        pub busy: bool,
        pub replies: usize,
    }

    impl FakeDevice {
        pub fn new() -> Self {
            let mut mux = Buffered::new(
                device::Mux::<NoiseBackend>::new(DEVICE_PROPERTIES).expect("device mux"),
            );
            mux.set_packet_len(PACKET_LEN);
            Self {
                state: Some(State::Mux(Box::new(mux))),
                outbox: VecDeque::new(),
                busy: false,
                replies: 0,
            }
        }

        /// True once the device has an established channel with no unacknowledged message.
        pub fn reply_acked(&self) -> bool {
            matches!(&self.state, Some(State::Open(ch)) if ch.sending_retry().is_none())
        }

        fn drain<C: trezor_thp::ChannelIO>(outbox: &mut VecDeque<Vec<u8>>, ch: &mut Buffered<C>) {
            while ch.packet_out_ready() {
                outbox.push_back(ch.packet_out().expect("device packet_out"));
            }
        }

        fn handle(&mut self, packet: &[u8]) {
            let state = self.state.take().expect("device state");
            self.state = Some(match state {
                State::Mux(mut mux) => {
                    mux.packet_in(packet);
                    Self::drain(&mut self.outbox, &mut mux);
                    if mux.channel_alloc_ready() {
                        let mut open = (*mux)
                            .map(|m| {
                                let mut m = m;
                                m.channel_alloc(CHANNEL_ID, AlwaysUnpaired)
                            })
                            .expect("device channel_alloc");
                        Self::drain(&mut self.outbox, &mut open);
                        State::Opening(Box::new(open))
                    } else {
                        State::Mux(mux)
                    }
                }
                State::Opening(mut open) => {
                    if let PacketInResult::HandshakeKeyRequired { .. } = open.packet_in(packet) {
                        open.set_static_key(&DEVICE_KEY).expect("device key");
                    }
                    Self::drain(&mut self.outbox, &mut *open);
                    if open.handshake_done() {
                        let channel = (*open).map(|o| o.complete()).expect("device complete");
                        State::Open(Box::new(channel))
                    } else {
                        State::Opening(open)
                    }
                }
                State::Open(mut ch) => {
                    if self.busy {
                        ch.send_error(trezor_thp::error::TransportError::TransportBusy);
                    } else if ch.packet_in(packet).got_message() {
                        let (session, _message_type, _payload) =
                            ch.message_out().expect("device message_out");
                        ch.message_in(session, MESSAGE_TYPE_SUCCESS, &[])
                            .expect("device reply");
                        self.replies += 1;
                    }
                    Self::drain(&mut self.outbox, &mut *ch);
                    State::Open(ch)
                }
            });
        }
    }

    pub const PACKET_LEN: usize = 244;

    impl PacketLink for FakeDevice {
        async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()> {
            self.handle(packet);
            Ok(())
        }

        async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>> {
            match self.outbox.pop_front() {
                Some(packet) => Ok(Some(packet)),
                None => {
                    tokio::time::sleep(wait).await;
                    Ok(None)
                }
            }
        }
    }

    /// Opens a host channel to the fake device through the production pump.
    pub async fn open_channel(device: &mut FakeDevice) -> Buffered<Channel<NoiseBackend>> {
        let timeout = Duration::from_secs(5);
        let mut mux = Buffered::new(Mux::<NoiseBackend>::new());
        mux.set_packet_len(PACKET_LEN);
        mux.request_channel(false);
        pump(device, &mut mux, timeout, |_, r| r.got_channel())
            .await
            .expect("allocate");
        let credentials = SharedCredentials::default();
        credentials.lock().static_key = [0x22; 32];
        let mut open = mux.map(|m| m.complete(credentials)).expect("channel open");
        pump(device, &mut open, timeout, |o, _| o.handshake_done())
            .await
            .expect("handshake");
        open.map(|o| o.complete()).expect("channel")
    }
}

#[tokio::test(start_paused = true)]
async fn final_response_is_acknowledged_before_returning() {
    let mut device = fake_device::FakeDevice::new();
    let mut channel = fake_device::open_channel(&mut device).await;

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let (message_type, _) = receive_message(&mut device, &mut channel, Duration::from_secs(5))
        .await
        .unwrap();

    assert_eq!(message_type, MESSAGE_TYPE_SUCCESS);
    assert_eq!(device.replies, 1);
    assert!(
        device.reply_acked(),
        "device is still waiting for the host to ACK its reply"
    );
}

#[tokio::test(start_paused = true)]
async fn repeated_transport_busy_stops_at_retry_limit() {
    let mut device = fake_device::FakeDevice::new();
    let mut channel = fake_device::open_channel(&mut device).await;
    device.busy = true;

    channel
        .message_in(SESSION_ID, messages::ThpCreateNewSession::MESSAGE_TYPE, &[])
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(3600),
        receive_message(&mut device, &mut channel, Duration::from_secs(5)),
    )
    .await
    .expect("busy retries must be bounded");

    assert!(matches!(result, Err(BackendError::TransportBusy)));
    assert_eq!(channel.sending_retry(), Some(MAX_RETRANSMISSION_COUNT - 1));
}
