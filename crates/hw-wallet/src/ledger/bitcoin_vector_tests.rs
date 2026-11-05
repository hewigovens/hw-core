use super::*;

// BIP143's native P2WPKH example. All expected bytes are published literals, not generated with SighashCache.
#[test]
fn bip143_published_signature_verifies_only_the_expected_input_and_amount() {
    let transaction: Transaction = bitcoin::consensus::deserialize(&hex::decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000").unwrap()).unwrap();
    let key =
        PublicKey::from_str("025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
            .unwrap();
    let signature = bitcoin::ecdsa::Signature::from_slice(&hex::decode("304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01").unwrap()).unwrap();
    let previous = TxOut {
        value: Amount::from_sat(600_000_000),
        script_pubkey: ScriptBuf::from_hex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap(),
    };
    let mut prepared = BitcoinTransaction {
        psbt: Psbt::from_unsigned_tx(transaction).unwrap(),
        keys: vec![key; 2],
    };
    // Both slots use the same key/amount so the wrong-index control tests the digest, not a key mismatch.
    for input in &mut prepared.psbt.inputs {
        input.witness_utxo = Some(previous.clone());
    }
    let mut cache = SighashCache::new(&prepared.psbt.unsigned_tx);
    let hash = cache
        .p2wpkh_signature_hash(
            1,
            &previous.script_pubkey,
            previous.value,
            EcdsaSighashType::All,
        )
        .unwrap();
    assert_eq!(
        hex::encode(hash.to_byte_array()),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    prepared
        .verify_signature(1, &signature, &mut cache)
        .unwrap();
    assert!(
        prepared
            .verify_signature(0, &signature, &mut cache)
            .is_err()
    );
    prepared.psbt.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_sat(600_000_001);
    assert!(
        prepared
            .verify_signature(1, &signature, &mut cache)
            .is_err()
    );
}
