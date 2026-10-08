use serde::Deserialize;

use super::*;
use crate::thp::backend::BackendError;
use crate::thp::proto::{
    BitcoinTxAck, BitcoinTxAckPaymentRequest, BitcoinTxRequestType, DecodedBitcoinTxRequest, TxAck,
    WireMessage,
};
use crate::thp::types::*;

fn sample_btc_sign_tx() -> BtcSignTx {
    BtcSignTx {
        version: 2,
        lock_time: 0,
        inputs: vec![BtcSignInput {
            path: vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
            prev_hash: vec![0x11; 32],
            prev_index: 0,
            amount: 1000,
            sequence: 0xffff_ffff,
            script_type: BtcInputScriptType::SpendWitness,
            multisig: None,
            script_sig: None,
            witness: None,
            orig_hash: Some(vec![0x33; 32]),
            orig_index: Some(0),
        }],
        outputs: vec![BtcSignOutput {
            address: Some("bc1qtest".to_string()),
            path: Vec::new(),
            amount: 900,
            script_type: BtcOutputScriptType::PayToAddress,
            multisig: None,
            op_return_data: None,
            orig_hash: Some(vec![0x33; 32]),
            orig_index: Some(0),
            payment_req_index: Some(0),
        }],
        ref_txs: vec![BtcRefTx {
            hash: vec![0x11; 32],
            version: 2,
            lock_time: 0,
            inputs: vec![BtcRefTxInput {
                prev_hash: vec![0x22; 32],
                prev_index: 0,
                script_sig: vec![0xaa],
                sequence: 0xffff_fffe,
            }],
            bin_outputs: vec![BtcRefTxOutput {
                amount: 1000,
                script_pubkey: vec![0x51],
            }],
            extra_data: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            timestamp: None,
            version_group_id: None,
            expiry: None,
            branch_id: None,
        }],
        orig_txs: vec![BtcOrigTx {
            hash: vec![0x33; 32],
            version: 2,
            lock_time: 0,
            inputs: vec![BtcSignInput {
                path: vec![0x8000_0054, 0x8000_0000, 0x8000_0000, 0, 0],
                prev_hash: vec![0x44; 32],
                prev_index: 0,
                amount: 1000,
                sequence: 0xffff_fffe,
                script_type: BtcInputScriptType::SpendWitness,
                multisig: None,
                script_sig: Some(vec![0xaa]),
                witness: Some(vec![0xbb]),
                orig_hash: None,
                orig_index: None,
            }],
            outputs: vec![BtcSignOutput {
                address: Some("bc1qorig".to_string()),
                path: Vec::new(),
                amount: 900,
                script_type: BtcOutputScriptType::PayToAddress,
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

fn tx_request(
    request_type: BitcoinTxRequestType,
    request_index: Option<u32>,
    tx_hash: Option<Vec<u8>>,
) -> DecodedBitcoinTxRequest {
    DecodedBitcoinTxRequest {
        request_type: Some(request_type),
        request_index,
        tx_hash,
        ..DecodedBitcoinTxRequest::default()
    }
}

fn sample_payment_request() -> BtcPaymentRequest {
    BtcPaymentRequest {
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
    }
}

#[test]
fn request_handling_acks_known_entries_and_rejects_unknown_ones() {
    use BitcoinTxRequestType::*;

    let mut btc = sample_btc_sign_tx();
    btc.payment_reqs = vec![sample_payment_request()];
    let prev = Some(vec![0x11; 32]);
    let orig = Some(vec![0x33; 32]);
    let cases = [
        (TxMeta, None, prev.clone(), Ok(BitcoinTxAck::MESSAGE_TYPE)),
        (
            TxOrigInput,
            Some(0),
            orig.clone(),
            Ok(BitcoinTxAck::MESSAGE_TYPE),
        ),
        (
            TxOrigOutput,
            Some(0),
            orig.clone(),
            Ok(BitcoinTxAck::MESSAGE_TYPE),
        ),
        (
            TxPaymentReq,
            Some(0),
            None,
            Ok(BitcoinTxAckPaymentRequest::MESSAGE_TYPE),
        ),
        (
            TxInput,
            Some(0),
            Some(vec![0x99; 32]),
            Err("TxInput request references unknown previous transaction hash"),
        ),
        (
            TxOutput,
            Some(2),
            prev.clone(),
            Err("TxOutput request index 2 out of bounds for previous transaction"),
        ),
        (
            TxOrigInput,
            Some(99),
            orig.clone(),
            Err("TxOrigInput request index 99 out of bounds"),
        ),
        (
            TxOrigOutput,
            Some(99),
            orig.clone(),
            Err("TxOrigOutput request index 99 out of bounds"),
        ),
        (
            TxPaymentReq,
            Some(1),
            None,
            Err("TxPaymentReq request index 1 out of bounds"),
        ),
    ];

    for (request_type, index, tx_hash, expected) in cases {
        let result = BitcoinTxSigner::new(&btc).handle(&tx_request(request_type, index, tx_hash));
        match (result, expected) {
            (Ok(BitcoinTxRequestHandling::Ack(ack)), Ok(message_type)) => {
                assert_eq!(ack.message_type, message_type, "{request_type:?}");
            }
            (Err(err), Err(message)) => {
                assert!(err.to_string().contains(message), "{request_type:?}: {err}");
            }
            (result, expected) => panic!("{request_type:?}: got {result:?}, expected {expected:?}"),
        }
    }
}

#[test]
fn signature_index_accepts_last_input_and_rejects_out_of_range() {
    let mut btc = sample_btc_sign_tx();
    btc.inputs.push(btc.inputs[0].clone());
    let signed = |signature_index: u32| DecodedBitcoinTxRequest {
        signature_index: Some(signature_index),
        signature: Some(vec![0xaa, 0xbb]),
        ..DecodedBitcoinTxRequest::default()
    };

    let mut signer = BitcoinTxSigner::new(&btc);
    signer.handle(&signed(1)).unwrap();
    assert_eq!(
        signer.into_response().signatures,
        vec![Vec::<u8>::new(), vec![0xaa, 0xbb]]
    );

    for signature_index in [2, u32::MAX] {
        let mut signer = BitcoinTxSigner::new(&btc);
        let err = signer.handle(&signed(signature_index)).unwrap_err();
        let BackendError::Device(message) = err else {
            panic!("expected device error");
        };
        assert_eq!(
            message,
            format!("device returned Bitcoin signature index {signature_index} for input count 2")
        );
        assert!(signer.into_response().signatures.is_empty());
    }
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

fn parse_input_script_type(value: &str) -> BtcInputScriptType {
    match value {
        "spendwitness" => BtcInputScriptType::SpendWitness,
        "spendaddress" => BtcInputScriptType::SpendAddress,
        "spendtaproot" => BtcInputScriptType::SpendTaproot,
        other => panic!("unsupported script_type: {other}"),
    }
}

fn parse_output_script_type(value: &str) -> BtcOutputScriptType {
    match value {
        "paytowitness" => BtcOutputScriptType::PayToWitness,
        "paytoaddress" => BtcOutputScriptType::PayToAddress,
        "paytotaproot" => BtcOutputScriptType::PayToTaproot,
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
    fn to_sign_input(&self) -> BtcSignInput {
        BtcSignInput {
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
    fn to_sign_output(&self) -> BtcSignOutput {
        BtcSignOutput {
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
    fn to_ref_tx(&self) -> BtcRefTx {
        BtcRefTx {
            hash: hex_to_bytes(&self.hash),
            version: self.version,
            lock_time: self.lock_time,
            inputs: self
                .inputs
                .iter()
                .map(|input| BtcRefTxInput {
                    prev_hash: hex_to_bytes(&input.prev_hash),
                    prev_index: input.prev_index,
                    script_sig: hex_to_bytes(&input.script_sig),
                    sequence: input.sequence,
                })
                .collect(),
            bin_outputs: self
                .bin_outputs
                .iter()
                .map(|output| BtcRefTxOutput {
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
    fn to_orig_tx(&self) -> BtcOrigTx {
        BtcOrigTx {
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
    fn to_memo(&self) -> BtcPaymentRequestMemo {
        match self.memo_type.as_str() {
            "text" => BtcPaymentRequestMemo::Text {
                text: self.text.clone().expect("text memo must include text"),
            },
            "text_details" => BtcPaymentRequestMemo::TextDetails {
                title: self
                    .title
                    .clone()
                    .expect("text_details memo must include title"),
                text: self
                    .text
                    .clone()
                    .expect("text_details memo must include text"),
            },
            "refund" => BtcPaymentRequestMemo::Refund {
                address: self
                    .address
                    .clone()
                    .expect("refund memo must include address"),
                path: parse_path(self.path.as_deref().expect("refund memo must include path")),
                mac: hex_to_bytes(self.mac.as_deref().expect("refund memo must include mac")),
            },
            "coin_purchase" => BtcPaymentRequestMemo::CoinPurchase {
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
    fn to_payment_request(&self) -> BtcPaymentRequest {
        BtcPaymentRequest {
            nonce: self.nonce.as_deref().map(hex_to_bytes),
            recipient_name: self.recipient_name.clone(),
            memos: self
                .memos
                .iter()
                .map(FixturePaymentRequestMemo::to_memo)
                .collect(),
            amount: self
                .amount
                .as_deref()
                .map(|amount| BtcPaymentRequestAmount::from_sats(amount.parse::<u64>().unwrap())),
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
    fn to_sign_tx(&self) -> BtcSignTx {
        BtcSignTx {
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
        "../../../../../tests/data/bitcoin/btc_rbf_with_payment_req.json"
    ))
}

fn load_extra_data_fixture() -> BtcFixture {
    parse_btc_fixture(include_str!(
        "../../../../../tests/data/bitcoin/btc_ref_tx_with_extra_data_sequence.json"
    ))
}

fn run_fixture_request_sequence(btc: &BtcSignTx, fixture: &BtcFixture) -> (u32, SignTxResponse) {
    let mut signer = BitcoinTxSigner::new(btc);
    let mut ack_count = 0u32;
    let mut finished = false;

    for (step, entry) in fixture.firmware_request_sequence.iter().enumerate() {
        let req_type_str = entry.request_type.as_str();
        let result = signer
            .handle(&entry.decoded_request())
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
    (ack_count, signer.into_response())
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

    let (ack_count, response) = run_fixture_request_sequence(&btc, &fixture);
    assert_eq!(ack_count, 14, "expected 14 ack responses in the sequence");
    assert!(response.r.is_empty(), "fixture does not emit signatures");
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

    let (ack_count, response) = run_fixture_request_sequence(&btc, &fixture);
    assert_eq!(ack_count, 5, "expected 5 ack responses in the sequence");
    assert_eq!(response.r, hex_to_bytes("0x3045022100feedface"));
}
