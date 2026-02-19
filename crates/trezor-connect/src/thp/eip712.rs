use std::{collections::BTreeMap, str::FromStr};

use num_bigint::BigInt;
use num_traits::{One, Signed};
use serde_json::Value as JsonValue;

use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{
    EthereumDataTypeProto, EthereumFieldType, EthereumStructMember, EthereumTypedDataStructAck,
};
use crate::thp::types::{Eip712StructMember, Eip712TypedData};

fn parse_array_type(type_name: &str) -> Option<(&str, Option<u32>)> {
    let stripped = type_name.strip_suffix(']')?;
    let start = stripped.rfind('[')?;
    let entry = &stripped[..start];
    let size_str = &stripped[start + 1..];
    if size_str.is_empty() {
        return Some((entry, None));
    }
    let size = size_str.parse::<u32>().ok()?;
    Some((entry, Some(size)))
}

fn parse_number_type(type_name: &str) -> Option<(bool, u32)> {
    if let Some(bits) = type_name.strip_prefix("uint") {
        let bits = if bits.is_empty() {
            256
        } else {
            bits.parse::<u32>().ok()?
        };
        return Some((false, bits));
    }
    if let Some(bits) = type_name.strip_prefix("int") {
        let bits = if bits.is_empty() {
            256
        } else {
            bits.parse::<u32>().ok()?
        };
        return Some((true, bits));
    }
    None
}

fn parse_bytes_type(type_name: &str) -> Option<Option<u32>> {
    let suffix = type_name.strip_prefix("bytes")?;
    if suffix.is_empty() {
        return Some(None);
    }
    Some(Some(suffix.parse::<u32>().ok()?))
}

fn parse_bigint_from_json(value: &JsonValue) -> BackendResult<BigInt> {
    match value {
        JsonValue::Number(number) => {
            if let Some(v) = number.as_i64() {
                return Ok(BigInt::from(v));
            }
            if let Some(v) = number.as_u64() {
                return Ok(BigInt::from(v));
            }
            Err(BackendError::Transport(format!(
                "unsupported non-integer JSON number for EIP-712 value: {number}"
            )))
        }
        JsonValue::String(s) => {
            if let Some(clean) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                BigInt::parse_bytes(clean.as_bytes(), 16).ok_or_else(|| {
                    BackendError::Transport(format!(
                        "invalid hexadecimal integer for EIP-712 value: {s}"
                    ))
                })
            } else {
                BigInt::from_str(s).map_err(|_| {
                    BackendError::Transport(format!(
                        "invalid decimal integer for EIP-712 value: {s}"
                    ))
                })
            }
        }
        _ => Err(BackendError::Transport(format!(
            "unsupported JSON value for EIP-712 integer: {value}"
        ))),
    }
}

fn bigint_to_fixed_bytes(value: BigInt, bytes: usize, signed: bool) -> BackendResult<Vec<u8>> {
    if bytes == 0 || bytes > 32 {
        return Err(BackendError::Transport(format!(
            "EIP-712 integer byte size must be within 1..=32, got {bytes}"
        )));
    }

    let bit_width = bytes * 8;
    let one = BigInt::one();
    let modulus = &one << bit_width;

    let encoded = if signed {
        let min = -(&one << (bit_width - 1));
        let max = (&one << (bit_width - 1)) - &one;
        if value < min || value > max {
            return Err(BackendError::Transport(format!(
                "signed integer overflow for EIP-712 value {value}"
            )));
        }
        if value.is_negative() {
            value + modulus
        } else {
            value
        }
    } else {
        if value.is_negative() {
            return Err(BackendError::Transport(format!(
                "cannot encode negative value {value} as unsigned EIP-712 integer"
            )));
        }
        if value >= modulus {
            return Err(BackendError::Transport(format!(
                "unsigned integer overflow for EIP-712 value {value}"
            )));
        }
        value
    };

    let (_, mut out) = encoded.to_bytes_be();
    if out.len() > bytes {
        return Err(BackendError::Transport(format!(
            "encoded integer size overflow: {} > {} bytes",
            out.len(),
            bytes
        )));
    }
    if out.len() < bytes {
        let mut padded = vec![0u8; bytes - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    Ok(out)
}

fn message_to_hex_bytes(message: &str) -> BackendResult<Vec<u8>> {
    let clean = if let Some(clean) = message
        .strip_prefix("0x")
        .or_else(|| message.strip_prefix("0X"))
    {
        clean
    } else if message.chars().all(|c| c.is_ascii_hexdigit()) {
        message
    } else {
        return Ok(message.as_bytes().to_vec());
    };

    let mut clean = clean.to_string();
    if clean.len() % 2 != 0 {
        clean.insert(0, '0');
    }
    hex::decode(clean)
        .map_err(|err| BackendError::Transport(format!("invalid hex string '{message}': {err}")))
}

fn json_member<'a>(value: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    value.as_object().and_then(|obj| obj.get(key))
}

fn encode_typed_data_value(
    type_name: &str,
    value: &JsonValue,
    types: &BTreeMap<String, Vec<Eip712StructMember>>,
) -> BackendResult<Vec<u8>> {
    if parse_array_type(type_name).is_some() {
        let array = value.as_array().ok_or_else(|| {
            BackendError::Transport(format!(
                "expected array value for EIP-712 type '{type_name}', got {value}"
            ))
        })?;
        return bigint_to_fixed_bytes(BigInt::from(array.len() as u64), 2, false);
    }

    if let Some(size) = parse_bytes_type(type_name) {
        let str_value = value.as_str().ok_or_else(|| {
            BackendError::Transport(format!(
                "expected string for EIP-712 bytes value '{type_name}', got {value}"
            ))
        })?;
        let bytes = message_to_hex_bytes(str_value)?;
        if let Some(size) = size
            && bytes.len() != size as usize
        {
            return Err(BackendError::Transport(format!(
                "invalid byte length for {type_name}: expected {size}, got {}",
                bytes.len()
            )));
        }
        return Ok(bytes);
    }

    if type_name == "address" {
        let str_value = value.as_str().ok_or_else(|| {
            BackendError::Transport(format!("expected string for EIP-712 address, got {value}"))
        })?;
        return message_to_hex_bytes(str_value);
    }
    if type_name == "string" {
        let str_value = value.as_str().ok_or_else(|| {
            BackendError::Transport(format!(
                "expected string for EIP-712 string value, got {value}"
            ))
        })?;
        return Ok(str_value.as_bytes().to_vec());
    }
    if type_name == "bool" {
        let bool_value = value.as_bool().ok_or_else(|| {
            BackendError::Transport(format!("expected bool for EIP-712 bool value, got {value}"))
        })?;
        return Ok(vec![if bool_value { 1 } else { 0 }]);
    }

    if let Some((signed, bits)) = parse_number_type(type_name) {
        let bytes = (bits as usize).div_ceil(8);
        let number = parse_bigint_from_json(value)?;
        return bigint_to_fixed_bytes(number, bytes, signed);
    }

    if types.contains_key(type_name) {
        return Err(BackendError::Transport(format!(
            "device requested struct value for '{type_name}', expected nested member path"
        )));
    }

    Err(BackendError::Transport(format!(
        "unsupported EIP-712 field type '{type_name}'"
    )))
}

fn field_type_from_type_name(
    type_name: &str,
    types: &BTreeMap<String, Vec<Eip712StructMember>>,
) -> BackendResult<EthereumFieldType> {
    if let Some((entry_type_name, array_size)) = parse_array_type(type_name) {
        let entry_type = field_type_from_type_name(entry_type_name, types)?;
        return Ok(EthereumFieldType {
            data_type: EthereumDataTypeProto::Array as i32,
            size: array_size,
            entry_type: Some(Box::new(entry_type)),
            struct_name: None,
        });
    }

    if let Some((signed, bits)) = parse_number_type(type_name) {
        let bytes = bits / 8;
        return Ok(EthereumFieldType {
            data_type: if signed {
                EthereumDataTypeProto::Int as i32
            } else {
                EthereumDataTypeProto::Uint as i32
            },
            size: Some(bytes),
            entry_type: None,
            struct_name: None,
        });
    }

    if let Some(size) = parse_bytes_type(type_name) {
        return Ok(EthereumFieldType {
            data_type: EthereumDataTypeProto::Bytes as i32,
            size,
            entry_type: None,
            struct_name: None,
        });
    }

    let data_type = match type_name {
        "string" => Some(EthereumDataTypeProto::String),
        "bool" => Some(EthereumDataTypeProto::Bool),
        "address" => Some(EthereumDataTypeProto::Address),
        _ => None,
    };
    if let Some(data_type) = data_type {
        return Ok(EthereumFieldType {
            data_type: data_type as i32,
            size: None,
            entry_type: None,
            struct_name: None,
        });
    }

    if let Some(members) = types.get(type_name) {
        return Ok(EthereumFieldType {
            data_type: EthereumDataTypeProto::Struct as i32,
            size: Some(members.len() as u32),
            entry_type: None,
            struct_name: Some(type_name.to_string()),
        });
    }

    Err(BackendError::Transport(format!(
        "missing EIP-712 type definition for '{type_name}'"
    )))
}

pub fn build_struct_ack(
    typed_data: &Eip712TypedData,
    struct_name: &str,
) -> BackendResult<EthereumTypedDataStructAck> {
    let members = typed_data.types.get(struct_name).ok_or_else(|| {
        BackendError::Transport(format!(
            "device requested undefined EIP-712 struct '{struct_name}'"
        ))
    })?;
    let members = members
        .iter()
        .map(|member| {
            let field_type = field_type_from_type_name(&member.type_name, &typed_data.types)?;
            Ok(EthereumStructMember {
                field_type,
                name: member.name.clone(),
            })
        })
        .collect::<BackendResult<Vec<_>>>()?;
    Ok(EthereumTypedDataStructAck { members })
}

pub fn resolve_value_for_member_path(
    typed_data: &Eip712TypedData,
    member_path: &[u32],
) -> BackendResult<Vec<u8>> {
    let (&root_index, nested_path) = member_path
        .split_first()
        .ok_or_else(|| BackendError::Transport("empty member_path in EIP-712 request".into()))?;

    let (mut current_value, mut current_type_name): (&JsonValue, &str) = match root_index {
        0 => (&typed_data.domain, "EIP712Domain"),
        1 => (&typed_data.message, typed_data.primary_type.as_str()),
        _ => {
            return Err(BackendError::Transport(format!(
                "invalid EIP-712 member_path root index {root_index}"
            )));
        }
    };

    for &index in nested_path {
        if let Some(array) = current_value.as_array() {
            let (entry_type_name, _) = parse_array_type(current_type_name).ok_or_else(|| {
                BackendError::Transport(format!(
                    "member_path traverses array but type '{current_type_name}' is not an array"
                ))
            })?;
            current_type_name = entry_type_name;
            current_value = array.get(index as usize).ok_or_else(|| {
                BackendError::Transport(format!(
                    "array index {index} out of bounds for EIP-712 member_path"
                ))
            })?;
            continue;
        }

        let struct_members = typed_data.types.get(current_type_name).ok_or_else(|| {
            BackendError::Transport(format!(
                "member_path traverses unknown struct type '{current_type_name}'"
            ))
        })?;
        let member = struct_members.get(index as usize).ok_or_else(|| {
            BackendError::Transport(format!(
                "member index {index} out of bounds for struct '{current_type_name}'"
            ))
        })?;
        current_type_name = member.type_name.as_str();
        current_value = json_member(current_value, &member.name).ok_or_else(|| {
            BackendError::Transport(format!(
                "member '{}' missing in EIP-712 value for struct '{current_type_name}'",
                member.name
            ))
        })?;
    }

    if current_value.is_array() {
        let len = current_value
            .as_array()
            .map(|arr| arr.len())
            .ok_or_else(|| BackendError::Transport("expected EIP-712 array value".into()))?;
        return bigint_to_fixed_bytes(BigInt::from(len as u64), 2, false);
    }

    encode_typed_data_value(current_type_name, current_value, &typed_data.types)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mail_typed_data() -> Eip712TypedData {
        Eip712TypedData {
            types: BTreeMap::from([
                (
                    "EIP712Domain".to_string(),
                    vec![
                        Eip712StructMember {
                            name: "name".to_string(),
                            type_name: "string".to_string(),
                        },
                        Eip712StructMember {
                            name: "chainId".to_string(),
                            type_name: "uint256".to_string(),
                        },
                    ],
                ),
                (
                    "Person".to_string(),
                    vec![
                        Eip712StructMember {
                            name: "wallet".to_string(),
                            type_name: "address".to_string(),
                        },
                        Eip712StructMember {
                            name: "age".to_string(),
                            type_name: "int8".to_string(),
                        },
                    ],
                ),
                (
                    "Mail".to_string(),
                    vec![
                        Eip712StructMember {
                            name: "from".to_string(),
                            type_name: "Person".to_string(),
                        },
                        Eip712StructMember {
                            name: "to".to_string(),
                            type_name: "Person[]".to_string(),
                        },
                        Eip712StructMember {
                            name: "active".to_string(),
                            type_name: "bool".to_string(),
                        },
                        Eip712StructMember {
                            name: "digest".to_string(),
                            type_name: "bytes32".to_string(),
                        },
                    ],
                ),
            ]),
            primary_type: "Mail".to_string(),
            domain: serde_json::json!({
                "name": "Ether Mail",
                "chainId": "1"
            }),
            message: serde_json::json!({
                "from": {
                    "wallet": "0x1111111111111111111111111111111111111111",
                    "age": -1
                },
                "to": [
                    {
                        "wallet": "0x2222222222222222222222222222222222222222",
                        "age": 34
                    },
                    {
                        "wallet": "0x3333333333333333333333333333333333333333",
                        "age": 35
                    }
                ],
                "active": true,
                "digest": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
            metamask_v4_compat: true,
            show_message_hash: None,
        }
    }

    #[test]
    fn suite_parity_parse_array_type() {
        assert_eq!(parse_array_type("uint8[26]"), Some(("uint8", Some(26))));
        assert_eq!(parse_array_type("int32[]"), Some(("int32", None)));
        assert_eq!(
            parse_array_type("int32[5][12]"),
            Some(("int32[5]", Some(12)))
        );
        assert_eq!(parse_array_type("bytes"), None);
    }

    #[test]
    fn suite_parity_struct_ack_field_type_mapping() {
        let typed_data = mail_typed_data();
        let ack = build_struct_ack(&typed_data, "Mail").unwrap();
        assert_eq!(ack.members.len(), 4);

        let from = &ack.members[0].field_type;
        assert_eq!(from.data_type, EthereumDataTypeProto::Struct as i32);
        assert_eq!(from.size, Some(2));
        assert_eq!(from.struct_name.as_deref(), Some("Person"));

        let to = &ack.members[1].field_type;
        assert_eq!(to.data_type, EthereumDataTypeProto::Array as i32);
        assert_eq!(to.size, None);
        let to_entry = to.entry_type.as_ref().unwrap();
        assert_eq!(to_entry.data_type, EthereumDataTypeProto::Struct as i32);
        assert_eq!(to_entry.struct_name.as_deref(), Some("Person"));
        assert_eq!(to_entry.size, Some(2));

        let active = &ack.members[2].field_type;
        assert_eq!(active.data_type, EthereumDataTypeProto::Bool as i32);

        let digest = &ack.members[3].field_type;
        assert_eq!(digest.data_type, EthereumDataTypeProto::Bytes as i32);
        assert_eq!(digest.size, Some(32));
    }

    #[test]
    fn suite_parity_member_path_value_encoding() {
        let typed_data = mail_typed_data();

        let domain_name = resolve_value_for_member_path(&typed_data, &[0, 0]).unwrap();
        assert_eq!(domain_name, b"Ether Mail");

        let from_wallet = resolve_value_for_member_path(&typed_data, &[1, 0, 0]).unwrap();
        assert_eq!(
            hex::encode(from_wallet),
            "1111111111111111111111111111111111111111"
        );

        let from_age = resolve_value_for_member_path(&typed_data, &[1, 0, 1]).unwrap();
        assert_eq!(from_age, vec![0xff]);

        let to_len = resolve_value_for_member_path(&typed_data, &[1, 1]).unwrap();
        assert_eq!(to_len, vec![0x00, 0x02]);

        let second_recipient_age =
            resolve_value_for_member_path(&typed_data, &[1, 1, 1, 1]).unwrap();
        assert_eq!(second_recipient_age, vec![35]);
    }

    #[test]
    fn suite_parity_reports_overflow_errors() {
        let mut typed_data = mail_typed_data();
        typed_data.message["from"]["age"] = serde_json::json!(128);
        let err = resolve_value_for_member_path(&typed_data, &[1, 0, 1]).unwrap_err();
        assert!(err.to_string().contains("overflow"));
    }
}
