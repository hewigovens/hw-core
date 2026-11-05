use super::LedgerSigningResult;
use crate::eth::EthSignTxExt;
use crate::{WalletError, WalletResult};
use ledger_connect::{ApduTransport, LedgerClient};
use sha3::{Digest, Keccak256};
use trezor_connect::thp::{EthDefinitionCatalog, EthDefinitions, EthSignTx, SignMessageResponse};

#[allow(async_fn_in_trait)]
pub trait LedgerEthereumExt {
    async fn sign_eip1559(&mut self, request: &EthSignTx) -> WalletResult<LedgerSigningResult>;
    async fn sign_verified_message(
        &mut self,
        path: &[u32],
        message: &[u8],
    ) -> WalletResult<SignMessageResponse>;
}

impl<T: ApduTransport> LedgerEthereumExt for LedgerClient<T> {
    async fn sign_eip1559(&mut self, request: &EthSignTx) -> WalletResult<LedgerSigningResult> {
        if request.definitions != EthDefinitions::default()
            || request.definition_catalog != EthDefinitionCatalog::default()
            || request.chunkify
        {
            return Err(WalletError::Signing(
                "Trezor display options and definitions are not supported by Ledger".into(),
            ));
        }
        if request.chain_id == 0
            || [
                &request.nonce,
                &request.value,
                &request.gas_limit,
                &request.max_fee_per_gas,
                &request.max_priority_fee,
            ]
            .iter()
            .any(|value| value.len() > 32)
        {
            return Err(WalletError::Signing(
                "invalid chain ID or Ethereum quantity exceeds 256 bits".into(),
            ));
        }
        if request
            .access_list
            .iter()
            .any(|entry| entry.storage_keys.iter().any(|key| key.len() != 32))
        {
            return Err(WalletError::Signing(
                "access-list storage keys must be 32 bytes".into(),
            ));
        }
        let unsigned = request.eip1559_payload()?;
        let account = self
            .ethereum_address(&request.path, false, request.chain_id)
            .await?;
        let signature = self.sign_transaction(&request.path, &unsigned).await?;
        LedgerSigningResult::verify(
            signature,
            Keccak256::digest(&unsigned).into(),
            &account.address,
        )?
        .with_transaction(&unsigned)
    }

    async fn sign_verified_message(
        &mut self,
        path: &[u32],
        message: &[u8],
    ) -> WalletResult<SignMessageResponse> {
        let account = self.ethereum_address(path, false, 1).await?;
        let signature = self.sign_personal_message(path, message).await?;
        let mut hash = Keccak256::new();
        hash.update(b"\x19Ethereum Signed Message:\n");
        hash.update(message.len().to_string().as_bytes());
        hash.update(message);
        let result =
            LedgerSigningResult::verify(signature, hash.finalize().into(), &account.address)?;
        Ok(SignMessageResponse {
            chain: hw_chain::Chain::Ethereum,
            signature: result.message_signature()?,
            address: result.recovered_address,
            signed_data: None,
        })
    }
}
