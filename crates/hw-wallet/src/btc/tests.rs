use trezor_connect::thp::{
    BtcHDNode, BtcInputScriptType, BtcMultisig, BtcMultisigPubkeysOrder, BtcOutputScriptType,
    BtcSignTx,
};

use super::owner::TxOwner;
use super::*;
use crate::error::WalletError;

const BTC_PARSE_WITH_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_parse_with_ref_txs.json");
const BTC_BUILD_WITH_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_build_with_ref_txs.json");
const BTC_MISSING_REF_TXS: &str =
    include_str!("../../../../tests/data/bitcoin/btc_missing_ref_txs.json");
const BTC_PREV_INDEX_OOB: &str =
    include_str!("../../../../tests/data/bitcoin/btc_prev_index_oob.json");
const BTC_RBF_WITH_PAYMENT_REQ: &str =
    include_str!("../../../../tests/data/bitcoin/btc_rbf_with_payment_req.json");
const BTC_MULTISIG_SIGN: &str =
    include_str!("../../../../tests/data/bitcoin/btc_multisig_sign.json");

#[test]
fn parse_btc_tx_json() {
    let tx = TxInput::from_json(BTC_PARSE_WITH_REF_TXS).unwrap();
    assert_eq!(tx.version, 2);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.ref_txs.len(), 1);
}

#[test]
fn build_btc_sign_request() {
    let tx = TxInput::from_json(BTC_BUILD_WITH_REF_TXS).unwrap();
    let btc = BtcSignTx::try_from(tx).unwrap();
    assert_eq!(btc.inputs[0].amount, 100);
    assert_eq!(btc.outputs[0].amount, 90);
    assert_eq!(
        btc.outputs[0].script_type,
        BtcOutputScriptType::PayToWitness
    );
    assert_eq!(btc.ref_txs.len(), 1);
}

fn output(address: Option<&str>, path: Option<&str>, script_type: Option<&str>) -> TxInputOutput {
    TxInputOutput {
        address: address.map(str::to_string),
        path: path.map(str::to_string),
        amount: "1000".to_string(),
        script_type: script_type.map(str::to_string),
        multisig: None,
        op_return_data: None,
        orig_hash: None,
        orig_index: None,
        payment_req_index: None,
    }
}

const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

#[test]
fn external_output_defaults_to_pay_to_address() {
    for script_type in [None, Some("paytoaddress"), Some("PAYTOADDRESS")] {
        let built = output(Some(ADDRESS), None, script_type)
            .into_sign_output(TxOwner::Signing)
            .unwrap();
        assert_eq!(built.script_type, BtcOutputScriptType::PayToAddress);
    }
}

#[test]
fn external_output_rejects_non_pay_to_address_script_types() {
    for (owner, script_type) in [
        (TxOwner::Signing, "paytowitness"),
        (TxOwner::Signing, "paytop2shwitness"),
        (TxOwner::Signing, "paytotaproot"),
        (TxOwner::Signing, "paytoscripthash"),
        (TxOwner::Signing, "paytomultisig"),
        (TxOwner::Signing, "paytoopreturn"),
        (TxOwner::Original, "paytowitness"),
    ] {
        let err = output(Some(ADDRESS), None, Some(script_type))
            .into_sign_output(owner)
            .unwrap_err();
        assert!(
            matches!(err, WalletError::Signing(_)),
            "{script_type}: {err}"
        );
        assert!(
            err.to_string().contains(&format!(
                "{} with address must use script_type PayToAddress",
                owner.output_label()
            )),
            "{script_type}: {err}"
        );
    }
}

#[test]
fn change_output_derives_script_type_from_path_purpose() {
    for (path, expected) in [
        ("m/44'/0'/0'/1/0", BtcOutputScriptType::PayToAddress),
        ("m/49'/0'/0'/1/0", BtcOutputScriptType::PayToP2shWitness),
        ("m/84'/0'/0'/1/0", BtcOutputScriptType::PayToWitness),
        ("m/86'/0'/0'/1/0", BtcOutputScriptType::PayToTaproot),
        ("m/10025'/0'/0'/1'/1/0", BtcOutputScriptType::PayToTaproot),
        ("m/48'/0'/0'/1'/1/0", BtcOutputScriptType::PayToP2shWitness),
        ("m/48'/0'/0'/2'/1/0", BtcOutputScriptType::PayToWitness),
        ("m/48'/0'/0'/3'/1/0", BtcOutputScriptType::PayToAddress),
        ("m/0/1", BtcOutputScriptType::PayToAddress),
    ] {
        let built = output(None, Some(path), None)
            .into_sign_output(TxOwner::Signing)
            .unwrap();
        assert_eq!(built.script_type, expected, "{path}");
    }
}

#[test]
fn change_output_derives_multisig_script_type_for_bip48_legacy_path() {
    let err = output(None, Some("m/48'/0'/0'/0'/1/0"), None)
        .into_sign_output(TxOwner::Signing)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("PayToMultisig output requires multisig metadata")
    );
}

#[test]
fn change_output_keeps_explicit_change_script_type() {
    for (script_type, expected) in [
        ("paytoaddress", BtcOutputScriptType::PayToAddress),
        ("paytop2shwitness", BtcOutputScriptType::PayToP2shWitness),
        ("paytowitness", BtcOutputScriptType::PayToWitness),
        ("paytotaproot", BtcOutputScriptType::PayToTaproot),
    ] {
        let built = output(None, Some("m/84'/0'/0'/1/0"), Some(script_type))
            .into_sign_output(TxOwner::Signing)
            .unwrap();
        assert_eq!(built.script_type, expected, "{script_type}");
    }
}

#[test]
fn change_output_rejects_non_change_script_types() {
    for script_type in ["paytoopreturn", "paytoscripthash"] {
        let err = output(None, Some("m/84'/0'/0'/1/0"), Some(script_type))
            .into_sign_output(TxOwner::Signing)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("bitcoin output with path cannot use script_type"),
            "{script_type}: {err}"
        );
    }
}

#[test]
fn op_return_output_requires_no_address_or_path_and_data() {
    let mut op_return = output(None, None, Some("paytoopreturn"));
    op_return.amount = "0".to_string();
    op_return.op_return_data = Some("deadbeef".to_string());
    let built = op_return.into_sign_output(TxOwner::Signing).unwrap();
    assert_eq!(built.script_type, BtcOutputScriptType::PayToOpReturn);
    assert_eq!(built.op_return_data, Some(vec![0xde, 0xad, 0xbe, 0xef]));

    let err = output(None, None, Some("paytoopreturn"))
        .into_sign_output(TxOwner::Signing)
        .unwrap_err();
    assert!(err.to_string().contains("requires op_return_data"));

    let err = output(None, None, None)
        .into_sign_output(TxOwner::Signing)
        .unwrap_err();
    assert!(err.to_string().contains("requires either address or path"));
}

#[test]
fn op_return_output_requires_zero_amount() {
    for owner in [TxOwner::Signing, TxOwner::Original] {
        let mut op_return = output(None, None, Some("paytoopreturn"));
        op_return.op_return_data = Some("deadbeef".to_string());
        let err = op_return.into_sign_output(owner).unwrap_err();
        assert!(matches!(err, WalletError::Signing(_)), "{err}");
        assert!(
            err.to_string().contains(&format!(
                "{} with script_type PayToOpReturn must have zero amount, got 1000",
                owner.output_label()
            )),
            "{err}"
        );

        let mut op_return = output(None, None, Some("paytoopreturn"));
        op_return.amount = "0".to_string();
        op_return.op_return_data = Some("deadbeef".to_string());
        let built = op_return.into_sign_output(owner).unwrap();
        assert_eq!(built.amount, 0);
    }
}

#[test]
fn build_btc_sign_request_with_orig_txs_and_payment_reqs() {
    let tx = TxInput::from_json(BTC_RBF_WITH_PAYMENT_REQ).unwrap();
    let btc = BtcSignTx::try_from(tx).unwrap();
    assert_eq!(btc.orig_txs.len(), 1);
    assert_eq!(btc.payment_reqs.len(), 1);
    assert_eq!(
        btc.inputs[0].orig_hash.as_deref(),
        Some([0x11; 32].as_slice())
    );
    assert_eq!(btc.outputs[0].payment_req_index, Some(0));
}

#[test]
fn build_btc_sign_request_rejects_unresolvable_ref_txs() {
    for (fixture, expected) in [
        (
            BTC_MISSING_REF_TXS,
            "ref_txs must include transaction 1111111111111111111111111111111111111111111111111111111111111111",
        ),
        (
            BTC_PREV_INDEX_OOB,
            "input 0 prev_index 2 out of bounds for ref_txs hash",
        ),
    ] {
        let tx = TxInput::from_json(fixture).unwrap();
        let err = BtcSignTx::try_from(tx).unwrap_err();
        assert!(err.to_string().contains(expected), "{err}");
    }
}

#[test]
fn build_btc_sign_request_rejects_broken_tx_links() {
    type BreakLink = fn(&mut TxInput);
    let cases: [(BreakLink, &str); 4] = [
        (
            |tx| tx.ref_txs[1].hash = tx.ref_txs[0].hash.clone(),
            "duplicate ref_txs hash e3b0c442",
        ),
        (
            |tx| tx.inputs[0].orig_index = None,
            "inputs[0] must specify both orig_hash and orig_index",
        ),
        (
            |tx| tx.inputs[1].orig_index = Some(9),
            "orig_index 9 out of bounds for inputs[1]",
        ),
        (
            |tx| tx.outputs[1].orig_hash = Some("22".repeat(32)),
            "missing original transaction 2222",
        ),
    ];
    for (break_link, expected) in cases {
        let mut tx = TxInput::from_json(BTC_RBF_WITH_PAYMENT_REQ).unwrap();
        break_link(&mut tx);
        let err = BtcSignTx::try_from(tx).unwrap_err();
        assert!(err.to_string().contains(expected), "{expected}: {err}");
    }
}

#[test]
fn build_btc_sign_request_with_multisig_input_and_output() {
    let tx = TxInput::from_json(BTC_MULTISIG_SIGN).unwrap();
    let btc = BtcSignTx::try_from(tx).unwrap();

    assert_eq!(btc.inputs.len(), 1);
    assert_eq!(btc.inputs[0].script_type, BtcInputScriptType::SpendMultisig);
    let input_ms = btc.inputs[0].multisig.as_ref().expect("input multisig");
    assert_eq!(input_ms.m, 2);
    assert_eq!(input_ms.pubkeys.len(), 3);
    assert_eq!(input_ms.signatures.len(), 3);
    assert_eq!(input_ms.pubkeys_order, BtcMultisigPubkeysOrder::Preserved);
    assert!(input_ms.signatures.iter().all(|s| s.is_empty()));
    assert_eq!(input_ms.pubkeys[0].node.depth, 4);
    assert_eq!(input_ms.pubkeys[0].node.fingerprint, 0x9DFF_15C0);
    assert_eq!(input_ms.pubkeys[0].node.child_num, 0x8000_0000);
    assert_eq!(input_ms.pubkeys[0].address_n, vec![0, 0]);
    assert_eq!(input_ms.pubkeys[0].node.public_key.len(), 33);

    assert_eq!(btc.outputs[0].multisig, None);
    assert_eq!(btc.outputs[0].amount, 90_000);

    assert_eq!(
        btc.outputs[1].script_type,
        BtcOutputScriptType::PayToMultisig
    );
    let output_ms = btc.outputs[1].multisig.as_ref().expect("output multisig");
    assert_eq!(output_ms.m, 2);
    assert_eq!(output_ms.nodes.len(), 3);
    assert_eq!(output_ms.address_n, vec![1, 0]);
    assert_eq!(
        output_ms.pubkeys_order,
        BtcMultisigPubkeysOrder::Lexicographic
    );
    assert!(output_ms.pubkeys.is_empty());
}

fn hd_node(chain_code: String, public_key: String) -> TxInputHDNode {
    TxInputHDNode {
        depth: 0,
        fingerprint: 0,
        child_num: 0,
        chain_code,
        public_key,
    }
}

fn valid_hd_node() -> TxInputHDNode {
    hd_node("00".repeat(32), format!("02{}", "00".repeat(32)))
}

#[test]
fn multisig_rejects_invalid_threshold_or_cosigners() {
    for (m, cosigners, expected) in [
        (0, 1, "threshold m must be at least 1"),
        (2, 0, "requires at least one cosigner"),
        (5, 1, "threshold m=5 exceeds number of cosigners n=1"),
    ] {
        let ms = TxInputMultisig {
            pubkeys: (0..cosigners)
                .map(|_| TxInputHDNodePath {
                    node: TxInputHDNodeRef::Node(valid_hd_node()),
                    address_n: vec![],
                })
                .collect(),
            signatures: vec![],
            m,
            nodes: vec![],
            address_n: vec![],
            pubkeys_order: TxInputMultisigPubkeysOrder::Preserved,
        };
        let err = BtcMultisig::try_from(ms).unwrap_err();
        assert!(err.to_string().contains(expected), "{err}");
    }
}

#[test]
fn parse_hd_node_ref_decodes_xpub_string() {
    let node = BtcHDNode::try_from(&TxInputHDNodeRef::Xpub(
        "tpubDF4tYm8PaDydbLMZZRqcquYZ6AvxFmyTv6RhSokPh6YxccaCxP1gF2VABKV9wsinAdUbsbdLx1vcXdJH8qRcQMM9VYd926rWM685CepPUdN"
            .to_string(),
    ))
    .unwrap();
    assert_eq!(node.depth, 4);
    assert_eq!(node.fingerprint, 0x9DFF_15C0);
    assert_eq!(node.child_num, 0x8000_0000);
    assert_eq!(node.chain_code.len(), 32);
    assert_eq!(node.public_key.len(), 33);
    assert_eq!(node.public_key[0], 0x03);
}

#[test]
fn parse_hd_node_ref_rejects_invalid_xpub_checksum() {
    let err = BtcHDNode::try_from(&TxInputHDNodeRef::Xpub(
        "tpubDF4tYm8PaDydbLMZZRqcquYZ6AvxFmyTv6RhSokPh6YxccaCxP1gF2VABKV9wsinAdUbsbdLx1vcXdJH8qRcQMM9VYd926rWM685CepPUdA"
            .to_string(),
    ))
    .unwrap_err();
    assert!(err.to_string().contains("checksum mismatch"));
}

#[test]
fn hd_node_rejects_bad_key_material_lengths() {
    for (node, expected) in [
        (
            hd_node("aabb".into(), format!("02{}", "00".repeat(32))),
            "chain_code length: expected 32 bytes, got 2",
        ),
        (
            hd_node("00".repeat(32), "00".repeat(32)),
            "public_key length: expected 33 bytes, got 32",
        ),
    ] {
        let err = BtcHDNode::try_from(&node).unwrap_err();
        assert!(err.to_string().contains(expected), "{err}");
    }
}
