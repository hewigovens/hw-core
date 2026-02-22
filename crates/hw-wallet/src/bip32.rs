use crate::error::{WalletError, WalletResult};

/// The hardened-key bit flag defined by BIP-32 (2^31).
const HARDENED: u32 = 0x8000_0000;

/// Parses a BIP-32 derivation path string into a vector of 32-bit child-key
/// indices.
///
/// # Format
///
/// The path may optionally begin with `"m/"` (master key prefix). Each
/// component is a decimal integer optionally followed by `'`, `h`, or `H` to
/// denote a hardened child.
///
/// | Input example         | Parsed indices               |
/// |-----------------------|------------------------------|
/// | `"m/44'/60'/0'/0/0"`  | `[0x8000002c, 0x8000003c, 0x80000000, 0, 0]` |
/// | `"44h/1/2H"`          | `[0x8000002c, 1, 0x80000002]`              |
/// | `"m"`                 | `[]` (master key, no children)             |
///
/// # Errors
///
/// Returns [`WalletError::InvalidBip32Path`] if:
/// - the path is empty,
/// - any segment is empty (double `/`),
/// - a segment cannot be parsed as a `u32`,
/// - a segment's numeric value is ≥ 2^31 (which would overflow into the
///   hardened range after the flag is applied).
pub fn parse_bip32_path(path: &str) -> WalletResult<Vec<u32>> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(WalletError::InvalidBip32Path("path is empty".to_string()));
    }

    let body = if trimmed == "m" {
        return Ok(Vec::new());
    } else if let Some(rest) = trimmed.strip_prefix("m/") {
        rest
    } else {
        trimmed
    };

    let mut result = Vec::new();
    for segment in body.split('/') {
        if segment.is_empty() {
            return Err(WalletError::InvalidBip32Path(format!(
                "empty segment in '{path}'"
            )));
        }

        let hardened = segment.ends_with('\'') || segment.ends_with('h') || segment.ends_with('H');
        let number_str = if hardened {
            &segment[..segment.len() - 1]
        } else {
            segment
        };

        let value = number_str.parse::<u32>().map_err(|_| {
            WalletError::InvalidBip32Path(format!("invalid segment '{segment}' in '{path}'"))
        })?;
        if value >= HARDENED {
            return Err(WalletError::InvalidBip32Path(format!(
                "segment '{segment}' is out of range (must be < 2^31)"
            )));
        }

        result.push(if hardened { value | HARDENED } else { value });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hardened_and_non_hardened_segments() {
        let path = parse_bip32_path("m/44'/60'/0'/0/0").unwrap();
        assert_eq!(path, vec![44 | HARDENED, 60 | HARDENED, HARDENED, 0, 0]);
    }

    #[test]
    fn supports_h_suffix_and_path_without_m_prefix() {
        let path = parse_bip32_path("44h/1/2H").unwrap();
        assert_eq!(path, vec![44 | HARDENED, 1, 2 | HARDENED]);
    }
}
