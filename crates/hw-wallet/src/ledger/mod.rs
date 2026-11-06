mod bitcoin;
mod bitcoin_account;
mod bitcoin_address;
mod bitcoin_purpose;
mod bitcoin_transaction;
mod bitcoin_tx_result;
mod eip712_field;
mod eip712_kind;
mod prepared_typed_data;
mod signing;
mod signing_result;
mod solana;
mod typed_data;
mod wallet;

pub use bitcoin::LedgerBitcoinExt;
pub use bitcoin_address::LedgerBitcoinAddress;
pub use bitcoin_tx_result::LedgerBitcoinTxResult;
pub use ledger_connect::LedgerModel;
pub use signing::LedgerEthereumExt;
pub use signing_result::LedgerSigningResult;
pub use solana::LedgerSolanaExt;
pub use typed_data::LedgerTypedDataExt;
pub use wallet::LedgerWalletExt;

#[cfg(test)]
mod bitcoin_tests;
#[cfg(test)]
mod tests;
