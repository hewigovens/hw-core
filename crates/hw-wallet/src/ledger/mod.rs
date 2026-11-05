mod bitcoin;
mod bitcoin_account;
mod bitcoin_transaction;
pub use bitcoin::{LedgerBitcoinAddress, LedgerBitcoinExt, LedgerBitcoinTxResult};
mod eip712_field;
mod prepared_typed_data;
mod solana;
mod typed_data;
pub use solana::LedgerSolanaExt;
pub use typed_data::LedgerTypedDataExt;
mod signing;
mod signing_result;

pub use signing::LedgerEthereumExt;
pub use signing_result::LedgerSigningResult;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bitcoin_tests;
