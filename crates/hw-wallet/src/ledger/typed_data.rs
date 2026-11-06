use super::{LedgerSigningResult, prepared_typed_data::PreparedTypedData};
use crate::{WalletError, WalletResult};
use hw_chain::Chain;
use ledger_connect::{ApduTransport, LedgerClient};
use sha3::{Digest, Keccak256};
use trezor_connect::thp::{SignTypedDataPayload, SignTypedDataRequest, SignTypedDataResponse};

#[allow(async_fn_in_trait)]
pub trait LedgerTypedDataExt {
    async fn sign_verified_typed_data(
        &mut self,
        request: &SignTypedDataRequest,
    ) -> WalletResult<SignTypedDataResponse>;
}

impl<T: ApduTransport> LedgerTypedDataExt for LedgerClient<T> {
    async fn sign_verified_typed_data(
        &mut self,
        request: &SignTypedDataRequest,
    ) -> WalletResult<SignTypedDataResponse> {
        if request.chain != Chain::Ethereum || request.encoded_network.is_some() {
            return Err(WalletError::Signing(
                "Ledger EIP-712 requires Ethereum without Trezor network definitions".into(),
            ));
        }
        let (hash, prepared) = match &request.payload {
            SignTypedDataPayload::TypedData(data) => {
                let prepared = PreparedTypedData::new(data)?;
                (prepared.hash, Some(prepared))
            }
            SignTypedDataPayload::Hashes {
                domain_separator_hash,
                message_hash,
            } => {
                let message = message_hash
                    .as_ref()
                    .filter(|hash| hash.len() == 32)
                    .ok_or_else(|| {
                        WalletError::Signing(
                            "Ledger hash signing requires a 32-byte message hash".into(),
                        )
                    })?;
                if domain_separator_hash.len() != 32 {
                    return Err(WalletError::Signing("domain hash must be 32 bytes".into()));
                }
                let mut hash = Keccak256::new();
                hash.update([0x19, 1]);
                hash.update(domain_separator_hash);
                hash.update(message);
                (hash.finalize().into(), None)
            }
        };
        let account = self.ethereum_address(&request.path, false, 1).await?;
        let signature = match (&request.payload, prepared) {
            (_, Some(prepared)) => self.sign_eip712(&request.path, &prepared.commands).await?,
            (
                SignTypedDataPayload::Hashes {
                    domain_separator_hash,
                    message_hash: Some(message),
                },
                None,
            ) => {
                let domain: &[u8; 32] = domain_separator_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| WalletError::Signing("invalid domain hash".into()))?;
                let message: &[u8; 32] = message
                    .as_slice()
                    .try_into()
                    .map_err(|_| WalletError::Signing("invalid message hash".into()))?;
                self.sign_eip712_hashes(&request.path, domain, message)
                    .await?
            }
            _ => return Err(WalletError::Signing("missing typed data".into())),
        };
        let result = LedgerSigningResult::verify(signature, hash, &account.address)?;
        let signature = result.message_signature()?;
        Ok(SignTypedDataResponse {
            chain: Chain::Ethereum,
            address: result.recovered_address,
            signature,
        })
    }
}
