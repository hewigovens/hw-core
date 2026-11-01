use serde::{Deserialize, Deserializer};

use crate::{WalletError, WalletResult};

/// Serde `deserialize_with` for a hex string field.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    decode(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

/// Serde `deserialize_with` for an optional hex string field.
pub fn deserialize_optional<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| decode(&value))
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// Decodes byte data, rejecting odd-length input rather than guessing at the missing nibble.
pub fn decode(value: &str) -> WalletResult<Vec<u8>> {
    decode_digits(value.strip_prefix("0x").unwrap_or(value))
}

/// Decodes a big-endian integer. Quantities such as `0x0` may have an odd digit count, so unlike
/// [`decode`] this pads them.
pub fn decode_quantity(value: &str) -> WalletResult<Vec<u8>> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    let bytes = if digits.len().is_multiple_of(2) {
        decode_digits(digits)?
    } else {
        decode_digits(&format!("0{digits}"))?
    };
    if bytes.is_empty() {
        return Ok(vec![0]);
    }

    let start = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len() - 1);
    Ok(bytes[start..].to_vec())
}

fn decode_digits(digits: &str) -> WalletResult<Vec<u8>> {
    ::hex::decode(digits)
        .map_err(|err| WalletError::Signing(format!("invalid hex '{digits}': {err}")))
}

pub(crate) fn decode_hash32(field: &str, value: &str) -> WalletResult<Vec<u8>> {
    decode_fixed::<32>(field, value).map(Vec::from)
}

pub fn decode_fixed<const N: usize>(field: &str, value: &str) -> WalletResult<[u8; N]> {
    let decoded = decode(value)?;
    let len = decoded.len();
    decoded
        .try_into()
        .map_err(|_| WalletError::Signing(format!("{field} must be {N} bytes, got {len} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_handles_prefix_and_empty() {
        assert_eq!(decode("0x0001").unwrap(), vec![0, 1]);
        assert_eq!(decode("0x").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_rejects_odd_length_input() {
        for value in ["abc", "0x123", "0x0"] {
            assert!(decode(value).is_err(), "{value} should be rejected");
        }
        assert!(decode_fixed::<2>("field", "0x123").is_err());
    }

    #[test]
    fn decode_quantity_strips_leading_zeros_and_keeps_zero() {
        assert_eq!(decode_quantity("0x0001").unwrap(), vec![1]);
        assert_eq!(decode_quantity("0x0").unwrap(), vec![0]);
        assert_eq!(decode_quantity("0x123").unwrap(), vec![0x01, 0x23]);
        assert!(decode_quantity("0x0x12").is_err());
        assert_eq!(decode_quantity("0x").unwrap(), vec![0]);
    }
}
