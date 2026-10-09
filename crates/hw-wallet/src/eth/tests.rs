use k256::ecdsa::SigningKey;
use trezor_connect::thp::{EthSignTx, EthTxSignature};

use super::*;

const ETH_PARSE_MINIMAL: &str =
    include_str!("../../../../tests/data/ethereum/eth_parse_minimal.json");
const ETH_BUILD_SIGN_REQUEST: &str =
    include_str!("../../../../tests/data/ethereum/eth_build_sign_request.json");

#[test]
fn parse_tx_json_minimal() {
    let tx = TxInput::from_json(ETH_PARSE_MINIMAL).unwrap();
    assert_eq!(tx.to, "0xdead");
    assert_eq!(tx.chain_id, 1);
}

#[test]
fn into_sign_tx_decodes_json_quantities() {
    let tx = TxInput::from_json(ETH_BUILD_SIGN_REQUEST).unwrap();

    let path = vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
    let request = tx.into_sign_tx(path.clone()).unwrap();
    assert_eq!(request.path, path);
    assert_eq!(request.chain_id, 1);
    assert_eq!(request.nonce, vec![1]);
    assert_eq!(request.gas_limit, vec![0x52, 0x08]);
}

#[test]
fn verify_sign_tx_response_recovers_expected_address() {
    let request = EthSignTx::new(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
        .with_nonce(vec![0x01])
        .with_max_fee_per_gas(vec![0x3b, 0x9a, 0xca, 0x00])
        .with_max_priority_fee(vec![0x59, 0x68, 0x2f, 0x00])
        .with_gas_limit(vec![0x52, 0x08])
        .with_to("0x000000000000000000000000000000000000dead".into())
        .with_value(vec![0x00])
        .with_data(Vec::new());

    let tx_hash = request.eip1559_sighash().unwrap();
    let key_bytes =
        hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279ef4f8f6f1842f5f6d4").unwrap();
    let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
    let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&tx_hash);
    let response = EthTxSignature {
        v: u32::from(recovery_id.to_byte()),
        r: signature.r().to_bytes().to_vec(),
        s: signature.s().to_bytes().to_vec(),
    };

    let verified = VerifiedSignature::recover(&request, &response).unwrap();
    assert_eq!(
        verified.recovered_address,
        "0x5637C997D8aFf61a4EC7d606f461c1c75f2b8120"
    );
}
