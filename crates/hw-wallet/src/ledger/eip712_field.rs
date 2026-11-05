use crate::{WalletError, WalletResult};

pub(super) struct Eip712Field<'a> {
    pub base: &'a str,
    pub kind: u8,
    pub size: Option<u8>,
    pub dimensions: Vec<Option<u8>>,
}

impl<'a> Eip712Field<'a> {
    pub fn parse(name: &'a str) -> WalletResult<Self> {
        let (base, mut rest) = name.split_at(name.find('[').unwrap_or(name.len()));
        let mut dimensions = Vec::new();
        while !rest.is_empty() {
            let tail = rest.strip_prefix('[').ok_or_else(|| Self::invalid(name))?;
            let (len, next) = tail.split_once(']').ok_or_else(|| Self::invalid(name))?;
            let size = if len.is_empty() {
                None
            } else {
                Some(
                    len.parse::<u8>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| Self::invalid(name))?,
                )
            };
            dimensions.push(size);
            if dimensions.len() > 32 {
                return Err(Self::invalid(name));
            }
            rest = next;
        }
        let (kind, size) = match base {
            "address" => (3, None),
            "bool" => (4, None),
            "string" => (5, None),
            "bytes" => (7, None),
            _ if ["uint", "int"].iter().any(|prefix| {
                base.strip_prefix(prefix)
                    .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_digit()))
            }) =>
            {
                let signed = base.starts_with("int");
                let bits = base[if signed { 3 } else { 4 }..]
                    .parse::<u16>()
                    .map_err(|_| Self::invalid(name))?;
                if bits == 0 || bits > 256 || bits % 8 != 0 {
                    return Err(Self::invalid(name));
                }
                (if signed { 1 } else { 2 }, Some((bits / 8) as u8))
            }
            _ if base.strip_prefix("bytes").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            }) =>
            {
                let size = base[5..]
                    .parse::<u8>()
                    .ok()
                    .filter(|n| (1..=32).contains(n))
                    .ok_or_else(|| Self::invalid(name))?;
                (6, Some(size))
            }
            _ => {
                Self::validate_name(base)?;
                (0, None)
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
            self.kind
                | if self.size.is_some() { 0x40 } else { 0 }
                | if self.dimensions.is_empty() { 0 } else { 0x80 },
        ];
        if self.kind == 0 {
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
