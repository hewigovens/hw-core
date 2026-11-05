mod bitcoin;
mod bitcoin_transport;
mod ethereum_address;
mod ethereum_signature;
mod ledger_client;
mod solana;
mod typed_data;

pub use ethereum_address::EthereumAddress;
pub use ethereum_signature::EthereumSignature;
pub use ledger_client::LedgerClient;
pub use typed_data::Eip712Command;

#[cfg(test)]
mod bitcoin_tests;
#[cfg(test)]
mod tests;
