use super::bitcoin_transport::BitcoinTransport;
use crate::{ApduTransport, LedgerClient, LedgerError};
use bitcoin::{
    Address,
    address::NetworkUnchecked,
    bip32::{DerivationPath, Fingerprint, Xpub},
    psbt::Psbt,
    secp256k1::ecdsa::Signature,
};
use ledger_bitcoin_client::{
    SignPsbtYieldedObject, WalletPolicy, async_client::BitcoinClient, error::BitcoinClientError,
};

impl<T: ApduTransport + Send> LedgerClient<T> {
    async fn bitcoin_request<R>(
        &mut self,
        testnet: bool,
        operation: impl AsyncFnOnce(
            &BitcoinClient<BitcoinTransport<'_, T>>,
        ) -> Result<R, BitcoinClientError<LedgerError>>,
    ) -> Result<R, LedgerError> {
        self.ensure_app(if testnet { "Bitcoin Test" } else { "Bitcoin" })
            .await?;
        self.ready = false;
        let client = BitcoinClient::new(BitcoinTransport::new(&mut self.transport));
        let result = operation(&client).await.map_err(|error| match error {
            BitcoinClientError::Transport(error) => error,
            BitcoinClientError::UnsupportedAppVersion => LedgerError::Unsupported,
            _ => LedgerError::Protocol("invalid Bitcoin app response or wallet policy"),
        });
        // An interrupted or cancelled Merkle exchange requires a new connection.
        if result.is_ok() {
            self.ready = true;
        }
        result
    }

    pub async fn bitcoin_master_fingerprint(
        &mut self,
        testnet: bool,
    ) -> Result<Fingerprint, LedgerError> {
        self.bitcoin_request(testnet, async |client| {
            client.get_master_fingerprint().await
        })
        .await
    }

    pub async fn bitcoin_extended_pubkey(
        &mut self,
        path: &DerivationPath,
        testnet: bool,
    ) -> Result<Xpub, LedgerError> {
        self.bitcoin_request(testnet, async |client| {
            client.get_extended_pubkey(path, false).await
        })
        .await
    }

    pub async fn bitcoin_wallet_address(
        &mut self,
        policy: &WalletPolicy,
        change: bool,
        index: u32,
        display: bool,
        testnet: bool,
    ) -> Result<Address<NetworkUnchecked>, LedgerError> {
        self.bitcoin_request(testnet, async |client| {
            client
                .get_wallet_address(policy, None, change, index, display)
                .await
        })
        .await
    }

    pub async fn sign_bitcoin_message(
        &mut self,
        path: &DerivationPath,
        message: &[u8],
        testnet: bool,
    ) -> Result<(u8, Signature), LedgerError> {
        if message.is_empty() || message.len() > 1024 * 1024 || path.len() > 10 {
            return Err(LedgerError::InvalidInput(
                "Bitcoin message must be 1 to 1048576 bytes with a path of at most 10 components",
            ));
        }
        self.bitcoin_request(testnet, async |client| {
            client.sign_message(message, path).await
        })
        .await
    }

    pub async fn sign_bitcoin_psbt(
        &mut self,
        psbt: &Psbt,
        policy: &WalletPolicy,
        testnet: bool,
    ) -> Result<Vec<(usize, SignPsbtYieldedObject)>, LedgerError> {
        self.bitcoin_request(testnet, async |client| {
            client.sign_psbt(psbt, policy, None).await
        })
        .await
    }
}
