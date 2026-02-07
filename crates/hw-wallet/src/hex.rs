use crate::{WalletError, WalletResult};

pub fn decode(value: &str) -> WalletResult<Vec<u8>> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    if stripped.is_empty() {
        return Ok(Vec::new());
    }

    let padded = if !stripped.len().is_multiple_of(2) {
        format!("0{stripped}")
    } else {
        stripped.to_owned()
    };

    ::hex::decode(&padded)
        .map_err(|err| WalletError::Signing(format!("invalid hex '{}': {err}", stripped)))
}

pub fn decode_quantity(value: &str) -> WalletResult<Vec<u8>> {
    let bytes = decode(value)?;
    if bytes.is_empty() {
        return Ok(vec![0]);
    }

    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len() - 1);
    Ok(bytes[start..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_handles_prefix_padding_and_empty() {
        assert_eq!(decode("0x0001").unwrap(), vec![0, 1]);
        assert_eq!(decode("abc").unwrap(), vec![0x0a, 0xbc]);
        assert_eq!(decode("0x").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_quantity_strips_leading_zeros_and_keeps_zero() {
        assert_eq!(decode_quantity("0x0001").unwrap(), vec![1]);
        assert_eq!(decode_quantity("0x0").unwrap(), vec![0]);
        assert_eq!(decode_quantity("0x").unwrap(), vec![0]);
    }
}
