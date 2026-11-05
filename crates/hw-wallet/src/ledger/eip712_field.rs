use super::eip712_kind::Eip712Kind;
use crate::{WalletError, WalletResult};
use trezor_connect::thp::types::Eip712TypeName;

pub(super) struct Eip712Field<'a> {
    pub base: &'a str,
    pub kind: Eip712Kind,
    pub size: Option<u8>,
    pub dimensions: Vec<Option<u8>>,
}

impl<'a> Eip712Field<'a> {
    pub fn parse(name: &'a str) -> WalletResult<Self> {
        let mut base = name;
        let mut dimensions = Vec::new();
        while let Some((entry, size)) = Eip712TypeName(base).array() {
            if !base[entry.len() + 1..base.len() - 1]
                .bytes()
                .all(|b| b.is_ascii_digit())
            {
                return Err(Self::invalid(name));
            }
            dimensions.push(
                size.map(|size| {
                    u8::try_from(size)
                        .ok()
                        .filter(|size| *size > 0)
                        .ok_or_else(|| Self::invalid(name))
                })
                .transpose()?,
            );
            if dimensions.len() > 32 {
                return Err(Self::invalid(name));
            }
            base = entry;
        }
        dimensions.reverse();
        Self::validate_name(base)?;
        let (kind, size) = match base {
            "address" => (Eip712Kind::Address, None),
            "bool" => (Eip712Kind::Bool, None),
            "string" => (Eip712Kind::String, None),
            _ => {
                if let Some((signed, bits)) = Eip712TypeName(base).number() {
                    // EIP-712 requires explicit widths; the shared Trezor parser also accepts aliases.
                    if matches!(base, "int" | "uint") || bits == 0 || bits > 256 || bits % 8 != 0 {
                        return Err(Self::invalid(name));
                    }
                    (
                        if signed {
                            Eip712Kind::Int
                        } else {
                            Eip712Kind::Uint
                        },
                        Some((bits / 8) as u8),
                    )
                } else if let Some(size) = Eip712TypeName(base).bytes() {
                    match size {
                        None => (Eip712Kind::Bytes, None),
                        Some(size) if (1..=32).contains(&size) => {
                            (Eip712Kind::FixedBytes, Some(size as u8))
                        }
                        _ => return Err(Self::invalid(name)),
                    }
                } else {
                    if ["uint", "int", "bytes"].iter().any(|prefix| {
                        base.strip_prefix(prefix)
                            .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_digit()))
                    }) {
                        return Err(Self::invalid(name));
                    }
                    (Eip712Kind::Struct, None)
                }
            }
        };
        Ok(Self {
            base,
            kind,
            size,
            dimensions,
        })
    }

    pub fn validate_name(name: &str) -> WalletResult<()> {
        if name.is_empty()
            || name.len() > 255
            || !name
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        {
            return Err(Self::invalid(name));
        }
        Ok(())
    }

    pub fn definition(&self, name: &str) -> WalletResult<Vec<u8>> {
        Self::validate_name(name)?;
        let mut out = vec![
            self.kind as u8
                | if self.size.is_some() { 0x40 } else { 0 }
                | if self.dimensions.is_empty() { 0 } else { 0x80 },
        ];
        if self.kind == Eip712Kind::Struct {
            out.push(self.base.len() as u8);
            out.extend(self.base.as_bytes());
        }
        if let Some(size) = self.size {
            out.push(size);
        }
        if !self.dimensions.is_empty() {
            out.push(self.dimensions.len() as u8);
            for size in &self.dimensions {
                match size {
                    Some(size) => out.extend([1, *size]),
                    None => out.push(0),
                }
            }
        }
        out.push(name.len() as u8);
        out.extend(name.as_bytes());
        if out.len() > 255 {
            return Err(Self::invalid(name));
        }
        Ok(out)
    }

    fn invalid(name: &str) -> WalletError {
        WalletError::Signing(format!(
            "unsupported or invalid Ledger EIP-712 type/name: {name}"
        ))
    }
}
