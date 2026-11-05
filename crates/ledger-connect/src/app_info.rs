use crate::LedgerError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAppInfo {
    pub name: String,
    pub version: String,
}

impl LedgerAppInfo {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        if bytes.first() != Some(&1) {
            return Err(LedgerError::Protocol("unsupported app-info format"));
        }
        let mut fields = &bytes[1..];
        let name = Self::field(&mut fields)?;
        let version = Self::field(&mut fields)?;
        if let Some((&length, flags)) = fields.split_first()
            && flags.len() != usize::from(length)
        {
            return Err(LedgerError::Protocol("invalid app-info flags"));
        }
        Ok(Self { name, version })
    }

    fn field(bytes: &mut &[u8]) -> Result<String, LedgerError> {
        let (&length, remainder) = bytes
            .split_first()
            .ok_or(LedgerError::Protocol("missing app-info field"))?;
        let length = usize::from(length);
        if length == 0 || length > remainder.len() {
            return Err(LedgerError::Protocol("invalid app-info field length"));
        }
        let value = std::str::from_utf8(&remainder[..length])
            .map_err(|_| LedgerError::Protocol("invalid app-info text"))?
            .to_owned();
        *bytes = &remainder[length..];
        Ok(value)
    }
}
