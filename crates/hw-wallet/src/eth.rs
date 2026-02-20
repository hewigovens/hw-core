use serde::Deserialize;
use trezor_connect::thp::{Chain, EthAccessListEntry, SignTxRequest, SignTxResponse};

use crate::error::{WalletError, WalletResult};
use crate::hex::{decode, decode_quantity};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

#[derive(Debug, Deserialize)]
pub struct TxInput {
    pub to: String,
    #[serde(default = "default_hex_zero")]
    pub value: String,
    #[serde(default = "default_hex_zero")]
    pub nonce: String,
    #[serde(default = "default_hex_zero")]
    pub gas_limit: String,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    #[serde(default = "default_hex_zero")]
    pub data: String,
    #[serde(default = "default_hex_zero")]
    pub max_fee_per_gas: String,
    #[serde(default = "default_hex_zero")]
    pub max_priority_fee: String,
    #[serde(default)]
    pub access_list: Vec<TxAccessListInput>,
}

#[derive(Debug, Deserialize)]
pub struct TxAccessListInput {
    pub address: String,
    #[serde(default)]
    pub storage_keys: Vec<String>,
}

fn default_hex_zero() -> String {
    "0x0".to_string()
}

fn default_chain_id() -> u64 {
    1
}

const EIP1559_TX_TYPE: u8 = 0x02;

pub fn parse_tx_json(json: &str) -> WalletResult<TxInput> {
    serde_json::from_str(json)
        .map_err(|err| WalletError::Signing(format!("invalid tx JSON: {err}")))
}

pub fn build_sign_tx_request(path: Vec<u32>, tx: TxInput) -> WalletResult<SignTxRequest> {
    let nonce = decode_quantity(&tx.nonce)?;
    let max_fee_per_gas = decode_quantity(&tx.max_fee_per_gas)?;
    let max_priority_fee = decode_quantity(&tx.max_priority_fee)?;
    let gas_limit = decode_quantity(&tx.gas_limit)?;
    let value = decode_quantity(&tx.value)?;
    let data = decode(&tx.data)?;

    let access_list: Vec<EthAccessListEntry> = tx
        .access_list
        .into_iter()
        .map(|entry| {
            let storage_keys = entry
                .storage_keys
                .iter()
                .map(|key| decode(key))
                .collect::<WalletResult<Vec<_>>>()?;
            Ok(EthAccessListEntry {
                address: entry.address,
                storage_keys,
            })
        })
        .collect::<WalletResult<Vec<_>>>()?;

    Ok(SignTxRequest::ethereum(path, tx.chain_id)
        .with_nonce(nonce)
        .with_max_fee_per_gas(max_fee_per_gas)
        .with_max_priority_fee(max_priority_fee)
        .with_gas_limit(gas_limit)
        .with_to(tx.to)
        .with_value(value)
        .with_data(data)
        .with_access_list(access_list))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifiedSignature {
    pub tx_hash: [u8; 32],
    pub recovered_address: String,
}

pub fn verify_sign_tx_response(
    request: &SignTxRequest,
    response: &SignTxResponse,
) -> WalletResult<VerifiedSignature> {
    if request.chain != Chain::Ethereum || response.chain != Chain::Ethereum {
        return Err(WalletError::Signing(
            "signature verification currently supports Ethereum only".into(),
        ));
    }
    if response.r.len() != 32 || response.s.len() != 32 {
        return Err(WalletError::Signing(
            "invalid signature length (expected 32-byte r/s)".into(),
        ));
    }

    let tx_hash = eip1559_sighash(request)?;
    let recovery_id = normalize_recovery_id(response.v)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&response.r);
    sig_bytes[32..].copy_from_slice(&response.s);
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|err| WalletError::Signing(format!("invalid signature bytes: {err}")))?;
    let verifying_key = VerifyingKey::recover_from_prehash(&tx_hash, &signature, recovery_id)
        .map_err(|err| WalletError::Signing(format!("failed to recover signer: {err}")))?;
    let recovered_address = verifying_key_to_checksum_address(&verifying_key)?;

    Ok(VerifiedSignature {
        tx_hash,
        recovered_address,
    })
}

fn eip1559_sighash(request: &SignTxRequest) -> WalletResult<[u8; 32]> {
    let mut rlp = RlpStream::new_list(9);
    append_quantity_u64(&mut rlp, request.chain_id);
    append_quantity_bytes(&mut rlp, &request.nonce);
    append_quantity_bytes(&mut rlp, &request.max_priority_fee);
    append_quantity_bytes(&mut rlp, &request.max_fee_per_gas);
    append_quantity_bytes(&mut rlp, &request.gas_limit);
    append_address(&mut rlp, &request.to)?;
    append_quantity_bytes(&mut rlp, &request.value);
    rlp.append(&request.data.as_slice());
    append_access_list(&mut rlp, &request.access_list)?;

    let payload = rlp.out();
    let mut typed_payload = Vec::with_capacity(payload.len() + 1);
    typed_payload.push(EIP1559_TX_TYPE);
    typed_payload.extend_from_slice(payload.as_ref());

    let hash = Keccak256::digest(typed_payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

fn append_quantity_u64(rlp: &mut RlpStream, value: u64) {
    if value == 0 {
        let empty: &[u8] = &[];
        rlp.append(&empty);
        return;
    }

    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    let quantity: &[u8] = &bytes[first..];
    rlp.append(&quantity);
}

fn append_quantity_bytes(rlp: &mut RlpStream, value: &[u8]) {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len());
    if first == value.len() {
        let empty: &[u8] = &[];
        rlp.append(&empty);
    } else {
        let quantity: &[u8] = &value[first..];
        rlp.append(&quantity);
    }
}

fn append_address(rlp: &mut RlpStream, value: &str) -> WalletResult<()> {
    if value.is_empty() {
        let empty: &[u8] = &[];
        rlp.append(&empty);
        return Ok(());
    }

    let address = decode(value)?;
    if address.len() != 20 {
        return Err(WalletError::Signing(format!(
            "invalid `to` address length {}; expected 20 bytes",
            address.len()
        )));
    }
    rlp.append(&address.as_slice());
    Ok(())
}

fn append_access_list(rlp: &mut RlpStream, entries: &[EthAccessListEntry]) -> WalletResult<()> {
    rlp.begin_list(entries.len());
    for entry in entries {
        let address = decode(&entry.address)?;
        if address.len() != 20 {
            return Err(WalletError::Signing(format!(
                "invalid access-list address length {}; expected 20 bytes",
                address.len()
            )));
        }
        rlp.begin_list(2);
        rlp.append(&address.as_slice());
        rlp.begin_list(entry.storage_keys.len());
        for key in &entry.storage_keys {
            rlp.append(&key.as_slice());
        }
    }
    Ok(())
}

fn normalize_recovery_id(v: u32) -> WalletResult<RecoveryId> {
    let parity = match v {
        0 | 1 => v as u8,
        27 | 28 => (v - 27) as u8,
        _ => {
            return Err(WalletError::Signing(format!(
                "unsupported signature `v` value: {v}"
            )));
        }
    };
    RecoveryId::try_from(parity)
        .map_err(|err| WalletError::Signing(format!("invalid recovery id: {err}")))
}

fn verifying_key_to_checksum_address(verifying_key: &VerifyingKey) -> WalletResult<String> {
    let pubkey = verifying_key.to_encoded_point(false);
    let bytes = pubkey.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(WalletError::Signing(
            "unexpected public key format while deriving address".into(),
        ));
    }

    let hash = Keccak256::digest(&bytes[1..]);
    let address = &hash[12..];
    Ok(to_checksum_address(address))
}

fn to_checksum_address(address: &[u8]) -> String {
    let lower = hex::encode(address);
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    let hash = Keccak256::digest(lower.as_bytes());

    for (idx, ch) in lower.chars().enumerate() {
        if ch.is_ascii_digit() {
            result.push(ch);
            continue;
        }

        let hash_byte = hash[idx / 2];
        let nibble = if idx % 2 == 0 {
            (hash_byte >> 4) & 0x0f
        } else {
            hash_byte & 0x0f
        };

        if nibble >= 8 {
            result.push(ch.to_ascii_uppercase());
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    const ETH_PARSE_MINIMAL: &str =
        include_str!("../../../tests/data/ethereum/eth_parse_minimal.json");
    const ETH_BUILD_SIGN_REQUEST: &str =
        include_str!("../../../tests/data/ethereum/eth_build_sign_request.json");

    #[test]
    fn parse_tx_json_minimal() {
        let tx = parse_tx_json(ETH_PARSE_MINIMAL).unwrap();
        assert_eq!(tx.to, "0xdead");
        assert_eq!(tx.chain_id, 1);
    }

    #[test]
    fn build_sign_tx_request_from_json() {
        let tx = parse_tx_json(ETH_BUILD_SIGN_REQUEST).unwrap();

        let path = vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0];
        let request = build_sign_tx_request(path.clone(), tx).unwrap();
        assert_eq!(request.path, path);
        assert_eq!(request.chain_id, 1);
        assert_eq!(request.nonce, vec![1]);
        assert_eq!(request.gas_limit, vec![0x52, 0x08]);
    }

    #[test]
    fn verify_sign_tx_response_recovers_expected_address() {
        let request = SignTxRequest::ethereum(vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0], 1)
            .with_nonce(vec![0x01])
            .with_max_fee_per_gas(vec![0x3b, 0x9a, 0xca, 0x00])
            .with_max_priority_fee(vec![0x59, 0x68, 0x2f, 0x00])
            .with_gas_limit(vec![0x52, 0x08])
            .with_to("0x000000000000000000000000000000000000dead".into())
            .with_value(vec![0x00])
            .with_data(Vec::new());

        let tx_hash = eip1559_sighash(&request).unwrap();
        let key_bytes =
            hex::decode("4c0883a69102937d6231471b5dbb6204fe512961708279ef4f8f6f1842f5f6d4")
                .unwrap();
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&tx_hash).unwrap();
        let response = SignTxResponse {
            chain: Chain::Ethereum,
            v: u32::from(recovery_id.to_byte()),
            r: signature.r().to_bytes().to_vec(),
            s: signature.s().to_bytes().to_vec(),
        };

        let verified = verify_sign_tx_response(&request, &response).unwrap();
        assert_eq!(
            verified.recovered_address,
            "0x5637C997D8aFf61a4EC7d606f461c1c75f2b8120"
        );
    }
}
