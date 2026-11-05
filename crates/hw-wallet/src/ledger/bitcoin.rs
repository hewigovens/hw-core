use super::{bitcoin_account::BitcoinAccount, bitcoin_transaction::BitcoinTransaction};
use crate::{WalletError, WalletResult};
use bitcoin::{
    Network,
    hashes::Hash,
    secp256k1::{
        Message, Secp256k1,
        ecdsa::{RecoverableSignature, RecoveryId},
    },
};
use ledger_connect::{ApduTransport, LedgerClient};
use trezor_connect::thp::{BtcSignTx, SignMessageRequest, SignMessageResponse};

pub struct LedgerBitcoinAddress {
    pub address: String,
    pub public_key: Vec<u8>,
}

pub struct LedgerBitcoinTxResult {
    /// DER signatures in input order, without the SIGHASH_ALL suffix.
    pub signatures: Vec<Vec<u8>>,
    pub serialized_transaction: Vec<u8>,
    pub transaction_id: String,
}

#[allow(async_fn_in_trait)]
pub trait LedgerBitcoinExt {
    async fn bitcoin_address(
        &mut self,
        path: &[u32],
        display: bool,
    ) -> WalletResult<LedgerBitcoinAddress>;
    async fn sign_verified_bitcoin_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse>;
    async fn sign_verified_bitcoin_transaction(
        &mut self,
        request: &BtcSignTx,
    ) -> WalletResult<LedgerBitcoinTxResult>;
}

impl<T: ApduTransport + Send> LedgerBitcoinExt for LedgerClient<T> {
    async fn bitcoin_address(
        &mut self,
        path: &[u32],
        display: bool,
    ) -> WalletResult<LedgerBitcoinAddress> {
        let account = BitcoinAccount::load(self, path).await?;
        let expected = account.address(path)?;
        let address = self
            .bitcoin_wallet_address(
                &account.policy,
                path[3] == 1,
                path[4],
                display,
                account.network != Network::Bitcoin,
            )
            .await?
            .require_network(account.network)
            .map_err(|_| WalletError::Signing("Ledger Bitcoin address network mismatch".into()))?;
        if address != expected {
            return Err(WalletError::Signing(
                "Ledger Bitcoin address does not match the account key".into(),
            ));
        }
        Ok(LedgerBitcoinAddress {
            address: address.to_string(),
            public_key: account.key(path)?.to_bytes(),
        })
    }

    async fn sign_verified_bitcoin_message(
        &mut self,
        request: &SignMessageRequest,
    ) -> WalletResult<SignMessageResponse> {
        BitcoinAccount::validate_path(&request.path)?;
        if request.chain != hw_chain::Chain::Bitcoin
            || request.chunkify
            || request.encoded_network.is_some()
            || !request.solana_signers.is_empty()
            || request.path[0] == (86 | 0x8000_0000)
        {
            return Err(WalletError::Signing("Ledger Bitcoin messages require a BIP44, BIP49 or BIP84 path without Trezor display options".into()));
        }
        let account = BitcoinAccount::load(self, &request.path).await?;
        let (header, signature) = self
            .sign_bitcoin_message(
                &BitcoinAccount::derivation(&request.path),
                &request.message,
                account.network != Network::Bitcoin,
            )
            .await?;
        if !(31..=34).contains(&header) {
            return Err(WalletError::Signing(
                "invalid Bitcoin message recovery header".into(),
            ));
        }
        let recovery = RecoveryId::from_i32(i32::from(header - 31))
            .map_err(|_| WalletError::Signing("invalid Bitcoin recovery id".into()))?;
        let recoverable =
            RecoverableSignature::from_compact(&signature.serialize_compact(), recovery)
                .map_err(|_| WalletError::Signing("invalid Bitcoin message signature".into()))?;
        let mut preimage = b"\x18Bitcoin Signed Message:\n".to_vec();
        preimage.extend(bitcoin::consensus::serialize(&bitcoin::VarInt(
            request.message.len() as u64,
        )));
        preimage.extend(&request.message);
        let hash = bitcoin::hashes::sha256d::Hash::hash(&preimage);
        let recovered = Secp256k1::verification_only()
            .recover_ecdsa(&Message::from_digest(hash.to_byte_array()), &recoverable)
            .map_err(|_| WalletError::Signing("invalid Bitcoin message signature".into()))?;
        if recovered != account.key(&request.path)?.inner {
            return Err(WalletError::Signing(
                "Ledger Bitcoin message signature does not match the requested key and payload"
                    .into(),
            ));
        }
        // BIP137 encodes the requested address type in the compact signature header.
        let offset = match request.path[0] & 0x7fff_ffff {
            49 => 4,
            84 => 8,
            _ => 0,
        };
        let mut bytes = vec![header + offset];
        bytes.extend(signature.serialize_compact());
        Ok(SignMessageResponse {
            chain: hw_chain::Chain::Bitcoin,
            address: account.address(&request.path)?.to_string(),
            signature: bytes,
            signed_data: None,
        })
    }

    async fn sign_verified_bitcoin_transaction(
        &mut self,
        request: &BtcSignTx,
    ) -> WalletResult<LedgerBitcoinTxResult> {
        BitcoinTransaction::validate(request)?;
        let account = BitcoinAccount::load(self, &request.inputs[0].path).await?;
        let prepared = BitcoinTransaction::new(request, &account)?;
        let signatures = self
            .sign_bitcoin_psbt(
                &prepared.psbt,
                &account.policy,
                account.network != Network::Bitcoin,
            )
            .await?;
        prepared.finish(signatures)
    }
}
