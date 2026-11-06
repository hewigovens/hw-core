use super::{LedgerBitcoinExt, LedgerEthereumExt, LedgerSolanaExt};
use crate::{WalletError, WalletResult};
use hw_chain::Chain;
use ledger_connect::{ApduTransport, LedgerClient};
use trezor_connect::thp::{
    EthTxSignature, GetAddressRequest, GetAddressResponse, SignMessageRequest, SignMessageResponse,
    SignTxRequest, SignTxResponse,
};

/// Shared request dispatch for Ledger adapters. Every signing response is verified locally.
#[allow(async_fn_in_trait)]
pub trait LedgerWalletExt {
    async fn get_address(
        &mut self,
        request: &GetAddressRequest,
    ) -> WalletResult<GetAddressResponse>;
    async fn sign_tx(&mut self, request: &SignTxRequest) -> WalletResult<SignTxResponse>;
    async fn sign_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse>;
}

impl<T: ApduTransport + Send> LedgerWalletExt for LedgerClient<T> {
    async fn get_address(
        &mut self,
        request: &GetAddressRequest,
    ) -> WalletResult<GetAddressResponse> {
        if request.chunkify || request.encoded_network.is_some() {
            return Err(WalletError::Unsupported(
                "Ledger addresses do not support Trezor display options".into(),
            ));
        }
        let (address, public_key) = match request.chain {
            Chain::Bitcoin => {
                let result = self
                    .bitcoin_address(&request.path, request.show_display)
                    .await?;
                (result.address, hex::encode(result.public_key))
            }
            Chain::Solana => {
                let address = self
                    .solana_address(&request.path, request.show_display)
                    .await?;
                (address.clone(), address)
            }
            Chain::Ethereum => {
                let result = self
                    .ethereum_address(&request.path, request.show_display, 1)
                    .await?;
                (
                    result.address,
                    format!("0x{}", hex::encode(result.public_key)),
                )
            }
        };
        Ok(GetAddressResponse {
            chain: request.chain,
            address,
            public_key: request.include_public_key.then_some(public_key),
            mac: None,
        })
    }

    async fn sign_tx(&mut self, request: &SignTxRequest) -> WalletResult<SignTxResponse> {
        Ok(match request {
            SignTxRequest::Ethereum(tx) => {
                let result = self.sign_eip1559(tx).await?;
                SignTxResponse::Ethereum(EthTxSignature {
                    v: u32::from(result.v),
                    r: result.r,
                    s: result.s,
                })
            }
            SignTxRequest::Bitcoin(tx) => {
                let result = self.sign_verified_bitcoin_transaction(tx).await?;
                SignTxResponse::Bitcoin {
                    last_signature: result.signatures.last().cloned().unwrap_or_default(),
                    signatures: result.signatures,
                }
            }
            SignTxRequest::Solana(tx) => SignTxResponse::Solana {
                signature: self.sign_verified_solana_transaction(tx).await?,
            },
        })
    }

    async fn sign_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse> {
        if request.chunkify
            || request.encoded_network.is_some()
            || (request.chain != Chain::Solana && !request.solana_signers.is_empty())
        {
            return Err(WalletError::Unsupported(
                "Ledger messages do not support Trezor display options".into(),
            ));
        }
        match request.chain {
            Chain::Ethereum => {
                self.sign_verified_message(&request.path, &request.message)
                    .await
            }
            Chain::Bitcoin => self.sign_verified_bitcoin_message(request).await,
            Chain::Solana => self.sign_verified_solana_message(request).await,
        }
    }
}
