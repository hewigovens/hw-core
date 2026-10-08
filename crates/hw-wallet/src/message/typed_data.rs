use std::collections::BTreeMap;

use hw_chain::Chain;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use trezor_connect::thp::{
    Eip712StructMember, Eip712TypedData, SignTypedDataRequest, SignTypedDataResponse,
};

use crate::chain::ChainPathExt;
use crate::error::{WalletError, WalletResult};
use crate::hex::decode_hash32;

pub trait SignTypedDataRequestExt: Sized {
    /// Builds an EIP-712 request from either `data_json` or the precomputed hashes.
    fn from_eip712(
        path: Vec<u32>,
        data_json: Option<&str>,
        domain_separator_hash: Option<&str>,
        message_hash: Option<&str>,
        metamask_v4_compat: bool,
    ) -> WalletResult<Self>;

    fn from_eip712_hashes(
        path: Vec<u32>,
        domain_separator_hash: &str,
        message_hash: Option<&str>,
    ) -> WalletResult<Self>;

    fn from_eip712_json(
        path: Vec<u32>,
        data_json: &str,
        metamask_v4_compat: bool,
    ) -> WalletResult<Self>;
}

impl SignTypedDataRequestExt for SignTypedDataRequest {
    fn from_eip712(
        path: Vec<u32>,
        data_json: Option<&str>,
        domain_separator_hash: Option<&str>,
        message_hash: Option<&str>,
        metamask_v4_compat: bool,
    ) -> WalletResult<Self> {
        match (data_json, domain_separator_hash, message_hash) {
            (Some(_), Some(_), _) | (Some(_), None, Some(_)) => Err(WalletError::Signing(
                "ETH EIP-712 signing must use either `data_json` or hash fields, not both".into(),
            )),
            (Some(data_json), None, None) => {
                Self::from_eip712_json(path, data_json, metamask_v4_compat)
            }
            (None, Some(domain_separator_hash), message_hash) => {
                Self::from_eip712_hashes(path, domain_separator_hash, message_hash)
            }
            (None, None, Some(_)) => Err(WalletError::Signing(
                "ETH EIP-712 hash signing requires `domain_separator_hash`".into(),
            )),
            (None, None, None) => Err(WalletError::Signing(
                "ETH EIP-712 signing requires either `data_json` or `domain_separator_hash`".into(),
            )),
        }
    }

    fn from_eip712_hashes(
        path: Vec<u32>,
        domain_separator_hash: &str,
        message_hash: Option<&str>,
    ) -> WalletResult<Self> {
        Chain::Ethereum.validate_signing_path(&path, "typed-data")?;
        let domain_separator_hash = decode_hash32("domain_separator_hash", domain_separator_hash)?;
        let message_hash = message_hash
            .map(|value| decode_hash32("message_hash", value))
            .transpose()?;
        Ok(Self::ethereum(path, domain_separator_hash, message_hash))
    }

    fn from_eip712_json(
        path: Vec<u32>,
        data_json: &str,
        metamask_v4_compat: bool,
    ) -> WalletResult<Self> {
        Chain::Ethereum.validate_signing_path(&path, "typed-data")?;

        let parsed: Eip712TypedDataInput = serde_json::from_str(data_json)
            .map_err(|err| WalletError::Signing(format!("invalid EIP-712 JSON: {err}")))?;
        let types = parsed
            .types
            .into_iter()
            .map(|(name, members)| {
                let members = members
                    .into_iter()
                    .map(|member| Eip712StructMember {
                        name: member.name,
                        type_name: member.type_name,
                    })
                    .collect();
                (name, members)
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
        Ok(Self::ethereum_typed_data(path, typed_data))
    }
}

pub trait SignTypedDataResponseExt {
    fn formatted_signature(&self) -> WalletResult<String>;
}

impl SignTypedDataResponseExt for SignTypedDataResponse {
    fn formatted_signature(&self) -> WalletResult<String> {
        if self.chain != Chain::Ethereum {
            return Err(WalletError::Signing(
                "typed-data signing currently supports Ethereum only".into(),
            ));
        }
        Ok(format!("0x{}", hex::encode(&self.signature)))
    }
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
