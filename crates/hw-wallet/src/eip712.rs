use hw_chain::Chain;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;
use trezor_connect::thp::{
    Eip712StructMember, Eip712TypedData, SignTypedDataRequest, SignTypedDataResponse,
};

use crate::chain::infer_chain_from_path;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode;

pub fn build_sign_typed_hash_request(
    path: Vec<u32>,
    domain_separator_hash: &str,
    message_hash: Option<&str>,
) -> WalletResult<SignTypedDataRequest> {
    validate_eth_path(&path)?;

    let domain_separator_hash = decode(domain_separator_hash)?;
    if domain_separator_hash.len() != 32 {
        return Err(WalletError::Signing(format!(
            "domain_separator_hash must be 32 bytes, got {} bytes",
            domain_separator_hash.len()
        )));
    }

    let message_hash = message_hash
        .map(decode)
        .transpose()?
        .map(|value| {
            if value.len() != 32 {
                Err(WalletError::Signing(format!(
                    "message_hash must be 32 bytes, got {} bytes",
                    value.len()
                )))
            } else {
                Ok(value)
            }
        })
        .transpose()?;

    Ok(SignTypedDataRequest::ethereum(
        path,
        domain_separator_hash,
        message_hash,
    ))
}

pub fn build_sign_typed_data_request(
    path: Vec<u32>,
    data_json: &str,
    metamask_v4_compat: bool,
) -> WalletResult<SignTypedDataRequest> {
    validate_eth_path(&path)?;

    let parsed: Eip712TypedDataInput = serde_json::from_str(data_json)
        .map_err(|err| WalletError::Signing(format!("invalid EIP-712 JSON: {err}")))?;

    let types = parsed
        .types
        .into_iter()
        .map(|(name, members)| {
            (
                name,
                members
                    .into_iter()
                    .map(|member| Eip712StructMember {
                        name: member.name,
                        type_name: member.type_name,
                    })
                    .collect(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    if !types.contains_key("EIP712Domain") {
        return Err(WalletError::Signing(
            "EIP-712 types must include EIP712Domain".into(),
        ));
    }
    if !types.contains_key(&parsed.primary_type) {
        return Err(WalletError::Signing(format!(
            "EIP-712 types missing primaryType '{}'",
            parsed.primary_type
        )));
    }

    let typed_data = Eip712TypedData {
        types,
        primary_type: parsed.primary_type,
        domain: parsed.domain,
        message: parsed.message.unwrap_or_else(|| serde_json::json!({})),
        metamask_v4_compat,
        show_message_hash: None,
    };

    Ok(SignTypedDataRequest::ethereum_typed_data(path, typed_data))
}

pub fn normalize_typed_data_signature(response: &SignTypedDataResponse) -> WalletResult<String> {
    if response.chain != Chain::Ethereum {
        return Err(WalletError::Signing(
            "typed-data signing currently supports Ethereum only".into(),
        ));
    }

    Ok(format!("0x{}", hex::encode(&response.signature)))
}

fn validate_eth_path(path: &[u32]) -> WalletResult<()> {
    if path.len() < 3 {
        return Err(WalletError::InvalidBip32Path(
            "typed-data path must contain at least 3 segments".to_string(),
        ));
    }

    if let Some(inferred) = infer_chain_from_path(path)
        && inferred != Chain::Ethereum
    {
        return Err(WalletError::InvalidBip32Path(format!(
            "chain/path mismatch: expected Ethereum, inferred {inferred:?}"
        )));
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Eip712TypedDataInput {
    #[serde(default)]
    types: BTreeMap<String, Vec<Eip712StructMemberInput>>,
    #[serde(rename = "primaryType")]
    primary_type: String,
    domain: JsonValue,
    #[serde(default)]
    message: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
struct Eip712StructMemberInput {
    name: String,
    #[serde(rename = "type")]
    type_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_sign_typed_hash_request_accepts_valid_hashes() {
        let request = build_sign_typed_hash_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            Some("0x2222222222222222222222222222222222222222222222222222222222222222"),
        )
        .unwrap();

        assert_eq!(request.chain, Chain::Ethereum);
        let trezor_connect::thp::SignTypedDataPayload::Hashes {
            domain_separator_hash,
            message_hash,
        } = request.payload
        else {
            panic!("expected hash payload");
        };
        assert_eq!(domain_separator_hash, vec![0x11; 32]);
        assert_eq!(message_hash, Some(vec![0x22; 32]));
    }

    #[test]
    fn build_sign_typed_hash_request_allows_domain_only_signing() {
        let request = build_sign_typed_hash_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            None,
        )
        .unwrap();

        let trezor_connect::thp::SignTypedDataPayload::Hashes { message_hash, .. } =
            request.payload
        else {
            panic!("expected hash payload");
        };
        assert_eq!(message_hash, None);
    }

    #[test]
    fn build_sign_typed_hash_request_rejects_bad_lengths() {
        let err = build_sign_typed_hash_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000],
            "0x1234",
            None,
        )
        .expect_err("short domain hash should fail");
        assert!(
            err.to_string()
                .contains("domain_separator_hash must be 32 bytes")
        );
    }

    #[test]
    fn normalize_typed_data_signature_as_hex() {
        let response = SignTypedDataResponse {
            chain: Chain::Ethereum,
            address: "0x1234".to_string(),
            signature: vec![0xaa, 0xbb],
        };

        let normalized = normalize_typed_data_signature(&response).unwrap();
        assert_eq!(normalized, "0xaabb");
    }

    #[test]
    fn build_sign_typed_data_request_accepts_full_json() {
        let request = build_sign_typed_data_request(
            vec![0x8000_002c, 0x8000_003c, 0x8000_0000, 0, 0],
            r#"{
                "types": {
                    "EIP712Domain": [{ "name": "name", "type": "string" }],
                    "Mail": [
                        { "name": "from", "type": "address" },
                        { "name": "contents", "type": "string" }
                    ]
                },
                "primaryType": "Mail",
                "domain": { "name": "Ether Mail" },
                "message": { "from": "0x1111111111111111111111111111111111111111", "contents": "hello" }
            }"#,
            true,
        )
        .unwrap();

        let trezor_connect::thp::SignTypedDataPayload::TypedData(typed) = request.payload else {
            panic!("expected typed-data payload");
        };
        assert_eq!(typed.primary_type, "Mail");
        assert!(typed.metamask_v4_compat);
        assert!(typed.types.contains_key("EIP712Domain"));
        assert!(typed.types.contains_key("Mail"));
    }
}
