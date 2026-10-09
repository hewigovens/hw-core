mod tx_signer;

pub(super) use tx_signer::{BitcoinTxRequestHandling, BitcoinTxSigner};

#[cfg(test)]
mod tests;
