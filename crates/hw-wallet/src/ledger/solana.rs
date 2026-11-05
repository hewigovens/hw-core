use crate::{WalletError, WalletResult, sol::SolanaSignTxExt};
use ed25519_dalek::{Signature, VerifyingKey};
use hw_chain::Chain;
use ledger_connect::{ApduTransport, LedgerClient, LedgerError};
use trezor_connect::thp::{SignMessageRequest, SignMessageResponse, SolanaSignTx};

#[allow(async_fn_in_trait)]
pub trait LedgerSolanaExt {
    async fn sign_verified_solana_transaction(
        &mut self,
        request: &SolanaSignTx,
    ) -> WalletResult<Vec<u8>>;
    async fn sign_verified_solana_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse>;
}

impl<T: ApduTransport> LedgerSolanaExt for LedgerClient<T> {
    async fn sign_verified_solana_transaction(
        &mut self,
        request: &SolanaSignTx,
    ) -> WalletResult<Vec<u8>> {
        if request.additional_info.is_some() {
            return Err(WalletError::Signing(
                "Trezor Solana token definitions are not supported by Ledger".into(),
            ));
        }
        SolanaSignTx::from_serialized_tx(request.path.clone(), request.serialized_tx.clone())?;
        let key = self.solana_public_key(&request.path, false).await?;
        let signature = self
            .sign_solana_transaction(&request.path, &request.serialized_tx)
            .await?;
        SolanaSignature::verify(&key, &signature, &request.serialized_tx)?;
        Ok(signature.to_vec())
    }

    async fn sign_verified_solana_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse> {
        if request.chain != Chain::Solana || request.chunkify || request.encoded_network.is_some() {
            return Err(WalletError::Signing(
                "Ledger Solana messages do not support Trezor display options".into(),
            ));
        }
        if request.message.is_empty()
            || std::str::from_utf8(&request.message).is_err()
            || request.solana_signers.len() > 255
        {
            return Err(WalletError::Signing(
                "Solana message must be nonempty UTF-8 with at most 255 signers".into(),
            ));
        }
        let mut signers = request.solana_signers.clone();
        signers.sort();
        if signers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(WalletError::Signing("duplicate Solana signer".into()));
        }
        let key = self.solana_public_key(&request.path, false).await?;
        if signers.is_empty() {
            signers.push(key);
        }
        if !signers.contains(&key) {
            return Err(WalletError::Signing(
                "requested Solana key is not in the signer list".into(),
            ));
        }
        let mut envelope = b"\xffsolana offchain".to_vec();
        envelope.extend([1, signers.len() as u8]);
        for signer in &signers {
            envelope.extend(signer);
        }
        envelope.extend(&request.message);
        let signature = self
            .sign_solana_offchain_message(&request.path, &envelope)
            .await
            .map_err(|error| match error {
                LedgerError::Status(0x6a81) => WalletError::Signing(
                    "Ledger Solana rejected the OCMS v1 header (0x6a81); use a Solana app version with OCMS v1 support, then reconnect. Legacy message formats are not substituted automatically".into(),
                ),
                error => error.into(),
            })?;
        SolanaSignature::verify(&key, &signature, &envelope)?;
        Ok(SignMessageResponse {
            chain: Chain::Solana,
            address: bs58::encode(key).into_string(),
            signature: signature.to_vec(),
            signed_data: Some(envelope),
        })
    }
}

struct SolanaSignature;
impl SolanaSignature {
    fn verify(key: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> WalletResult<()> {
        VerifyingKey::from_bytes(key)
            .and_then(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
            .map_err(|_| {
                WalletError::Signing(
                    "Ledger Solana signature does not match the requested key and payload".into(),
                )
            })
    }
}
