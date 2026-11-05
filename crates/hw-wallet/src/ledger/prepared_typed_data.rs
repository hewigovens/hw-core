use super::eip712_field::Eip712Field;
use crate::{WalletError, WalletResult};
use ledger_connect::Eip712Command;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::BTreeSet;
use trezor_connect::thp::Eip712TypedData;

pub(super) struct PreparedTypedData {
    pub commands: Vec<Eip712Command>,
    pub hash: [u8; 32],
}

impl PreparedTypedData {
    pub fn new(data: &Eip712TypedData) -> WalletResult<Self> {
        if !data.metamask_v4_compat
            || data.primary_type == "EIP712Domain"
            || data.show_message_hash.is_some()
        {
            return Err(WalletError::Signing("Ledger full EIP-712 requires v4 domain and message data without Trezor display options".into()));
        }
        let mut prepared = Self {
            commands: vec![],
            hash: [0; 32],
        };
        for (name, fields) in &data.types {
            Eip712Field::validate_name(name)?;
            prepared
                .commands
                .push(Eip712Command::StructName(name.clone()));
            let mut names = BTreeSet::new();
            for field in fields {
                if !names.insert(&field.name) {
                    return Err(WalletError::Signing("duplicate EIP-712 field name".into()));
                }
                let ty = Eip712Field::parse(&field.type_name)?;
                if ty.kind == 0 && !data.types.contains_key(ty.base) {
                    return Err(WalletError::Signing(format!(
                        "undefined EIP-712 struct {}",
                        ty.base
                    )));
                }
                prepared
                    .commands
                    .push(Eip712Command::StructField(ty.definition(&field.name)?));
            }
        }
        let mut hash = Keccak256::new();
        hash.update([0x19, 1]);
        for (index, name, value) in [
            (0, "EIP712Domain", &data.domain),
            (1, data.primary_type.as_str(), &data.message),
        ] {
            prepared.commands.push(Eip712Command::Root(name.into()));
            hash.update(prepared.value(data, name, value, &mut vec![index], 0)?);
        }
        prepared.hash = hash.finalize().into();
        Ok(prepared)
    }

    fn value(
        &mut self,
        data: &Eip712TypedData,
        name: &str,
        value: &Value,
        path: &mut Vec<u32>,
        depth: usize,
    ) -> WalletResult<[u8; 32]> {
        if depth > 64 || self.commands.len() >= 16384 {
            return Err(WalletError::Signing(
                "EIP-712 nesting or command limit exceeded".into(),
            ));
        }
        let ty = Eip712Field::parse(name)?;
        if let Some(size) = ty.dimensions.last() {
            let values = value
                .as_array()
                .ok_or_else(|| WalletError::Signing("expected EIP-712 array".into()))?;
            if values.len() > 255 || size.is_some_and(|size| usize::from(size) != values.len()) {
                return Err(WalletError::Signing(
                    "invalid Ledger EIP-712 array length (maximum 255)".into(),
                ));
            }
            self.commands.push(Eip712Command::Array(values.len() as u8));
            let entry = name
                .rsplit_once('[')
                .ok_or_else(|| WalletError::Signing("invalid array type".into()))?
                .0;
            let mut hash = Keccak256::new();
            for (index, value) in values.iter().enumerate() {
                path.push(index as u32);
                hash.update(self.value(data, entry, value, path, depth + 1)?);
                path.pop();
            }
            return Ok(hash.finalize().into());
        }
        if ty.kind == 0 {
            let fields = data
                .types
                .get(name)
                .ok_or_else(|| WalletError::Signing(format!("undefined EIP-712 struct {name}")))?;
            if !value.is_object() {
                return Err(WalletError::Signing(
                    "expected EIP-712 struct object".into(),
                ));
            }
            let mut hash = Keccak256::new();
            hash.update(Self::type_hash(data, name)?);
            for (index, field) in fields.iter().enumerate() {
                let value = value.get(&field.name).ok_or_else(|| {
                    WalletError::Signing(format!("missing EIP-712 field {}", field.name))
                })?;
                path.push(index as u32);
                hash.update(self.value(data, &field.type_name, value, path, depth + 1)?);
                path.pop();
            }
            return Ok(hash.finalize().into());
        }
        if value.is_array() || value.is_object() || value.is_null() {
            return Err(WalletError::Signing(format!(
                "expected scalar EIP-712 value for {name}"
            )));
        }
        let bytes = data
            .member_value(path)
            .map_err(|err| WalletError::Signing(err.to_string()))?;
        if bytes.len() > 65535 {
            return Err(WalletError::Signing(
                "EIP-712 field exceeds 65535 bytes".into(),
            ));
        }
        let mut encoded = [0; 32];
        match ty.kind {
            5 | 7 => encoded = Keccak256::digest(&bytes).into(),
            6 => encoded[..bytes.len()].copy_from_slice(&bytes),
            _ => {
                if ty.kind == 1 && bytes.first().is_some_and(|b| b & 0x80 != 0) {
                    encoded.fill(0xff);
                }
                encoded[32 - bytes.len()..].copy_from_slice(&bytes);
            }
        }
        self.commands.push(Eip712Command::Value(bytes));
        Ok(encoded)
    }

    fn type_hash(data: &Eip712TypedData, name: &str) -> WalletResult<[u8; 32]> {
        let mut deps = BTreeSet::new();
        let mut pending = vec![name];
        while let Some(current) = pending.pop() {
            if !deps.insert(current) {
                continue;
            }
            for field in data
                .types
                .get(current)
                .ok_or_else(|| WalletError::Signing("undefined EIP-712 struct".into()))?
            {
                let ty = Eip712Field::parse(&field.type_name)?;
                if ty.kind == 0 {
                    pending.push(ty.base);
                }
            }
        }
        deps.remove(name);
        let mut canonical = String::new();
        for name in std::iter::once(name).chain(deps) {
            canonical.push_str(name);
            canonical.push('(');
            let fields = data
                .types
                .get(name)
                .ok_or_else(|| WalletError::Signing("undefined EIP-712 struct".into()))?;
            for (i, field) in fields.iter().enumerate() {
                if i > 0 {
                    canonical.push(',');
                }
                canonical.push_str(&field.type_name);
                canonical.push(' ');
                canonical.push_str(&field.name);
            }
            canonical.push(')');
        }
        Ok(Keccak256::digest(canonical.as_bytes()).into())
    }
}
