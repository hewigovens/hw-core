use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Eip712TypedData {
    pub types: BTreeMap<String, Vec<Eip712StructMember>>,
    pub primary_type: String,
    pub domain: JsonValue,
    pub message: JsonValue,
    pub metamask_v4_compat: bool,
    pub show_message_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Eip712StructMember {
    pub name: String,
    pub type_name: String,
}
