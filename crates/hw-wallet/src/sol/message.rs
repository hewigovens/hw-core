use crate::{WalletError, WalletResult};

/// Validates a bare Solana message, excluding the transaction's signature envelope.
pub(crate) struct SolanaMessage<'a> {
    bytes: &'a [u8],
}

impl<'a> SolanaMessage<'a> {
    pub fn required_signers(bytes: &'a [u8]) -> WalletResult<Vec<[u8; 32]>> {
        let mut reader = Self { bytes };
        let first = reader.byte()?;
        let versioned = first & 0x80 != 0;
        let required = if versioned {
            if first != 0x80 {
                return Err(WalletError::Unsupported(
                    "Solana supports legacy and v0 messages".into(),
                ));
            }
            reader.byte()?
        } else {
            first
        } as usize;
        let readonly_signed = reader.byte()? as usize;
        let readonly_unsigned = reader.byte()? as usize;
        let accounts = reader.length()?;
        if required == 0
            || required > accounts
            || readonly_signed >= required
            || readonly_unsigned > accounts - required
            || accounts > 256
        {
            return Err(Self::invalid());
        }
        let mut signers = Vec::with_capacity(required);
        for _ in 0..required {
            signers.push(reader.take(32)?.try_into().map_err(|_| Self::invalid())?);
        }
        reader.take((accounts - required) * 32)?;
        reader.take(32)?;
        let instructions = reader.length()?;
        let mut indices = Vec::new();
        for _ in 0..instructions {
            indices.push(reader.byte()? as usize);
            let count = reader.length()?;
            indices.extend(reader.take(count)?.iter().map(|index| *index as usize));
            let data = reader.length()?;
            reader.take(data)?;
        }
        let mut total_accounts = accounts;
        if versioned {
            let lookups = reader.length()?;
            for _ in 0..lookups {
                reader.take(32)?;
                for _ in 0..2 {
                    let count = reader.length()?;
                    reader.take(count)?;
                    total_accounts += count;
                }
            }
        }
        if !reader.bytes.is_empty()
            || total_accounts > 256
            || indices.iter().any(|index| *index >= total_accounts)
        {
            return Err(Self::invalid());
        }
        Ok(signers)
    }

    fn invalid() -> WalletError {
        WalletError::Signing("Solana requires serialized message bytes (legacy or v0), without transaction signatures".into())
    }

    fn take(&mut self, count: usize) -> WalletResult<&'a [u8]> {
        if count > self.bytes.len() {
            return Err(Self::invalid());
        }
        let (value, rest) = self.bytes.split_at(count);
        self.bytes = rest;
        Ok(value)
    }

    fn byte(&mut self) -> WalletResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn length(&mut self) -> WalletResult<usize> {
        let mut value = 0usize;
        for index in 0..3 {
            let byte = self.byte()?;
            if (index == 2 && byte > 3) || (index > 0 && byte == 0) {
                return Err(Self::invalid());
            }
            value |= usize::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(Self::invalid())
    }
}
