use crate::error::{WalletError, WalletResult};

pub(super) fn parse_sats(value: &str) -> WalletResult<u64> {
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse::<u64>(),
    };
    parsed.map_err(|err| WalletError::Signing(format!("invalid satoshi amount '{value}': {err}")))
}
