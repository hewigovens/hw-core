use sha2::{Digest, Sha256};
use tracing::debug;

use super::backend::BleBackend;
use super::errors::MESSAGE_TYPE_FAILURE;
use super::nfc::NfcSecret;
use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::crypto::{CpaceHostKeys, validate_code_entry_tag, validate_qr_code_tag};
use crate::thp::messages;
use crate::thp::proto::{EncodedMessage, ParsedTagResponse, WireMessage};
use crate::thp::types::PairingTagResponse;

impl BleBackend {
    /// Generates the NFC secret for this channel and returns the data the host shares over NFC.
    pub(super) fn prepare_nfc_pairing(&mut self) -> BackendResult<Vec<u8>> {
        let handshake_hash = self.handshake_hash()?;
        let secret = NfcSecret::random();
        let nfc_data = secret.pairing_data(&handshake_hash)?;
        self.nfc_secret = Some(secret);
        Ok(nfc_data)
    }

    pub(super) async fn send_qr_code_tag(
        &mut self,
        handshake_hash: Vec<u8>,
        tag: String,
    ) -> BackendResult<PairingTagResponse> {
        let tag_bytes =
            hex::decode(&tag).map_err(|_| BackendError::Transport("invalid QR tag hex".into()))?;
        let message = messages::ThpQrCodeTag {
            tag: Sha256::new()
                .chain_update(&handshake_hash)
                .chain_update(&tag_bytes)
                .finalize()
                .to_vec(),
        }
        .to_message();
        self.exchange_tag(message, |secret| {
            if let Err(err) = validate_qr_code_tag(&handshake_hash, &tag_bytes, &secret) {
                debug!("QR tag validation failed: {err}");
                return Ok(PairingTagResponse::Retry("pairing tag mismatch".into()));
            }
            Ok(PairingTagResponse::Accepted { secret })
        })
        .await
    }

    pub(super) async fn send_nfc_tag(
        &mut self,
        handshake_hash: Vec<u8>,
        tag: String,
    ) -> BackendResult<PairingTagResponse> {
        let tag_bytes =
            hex::decode(&tag).map_err(|_| BackendError::Transport("invalid NFC tag hex".into()))?;
        let message = messages::ThpNfcTagHost {
            tag: Sha256::new()
                .chain_update([messages::ThpPairingMethod::Nfc as u8])
                .chain_update(&handshake_hash)
                .chain_update(&tag_bytes)
                .finalize()
                .to_vec(),
        }
        .to_message();
        let nfc_secret = self.nfc_secret;
        self.exchange_tag(message, |secret| {
            let nfc_secret = nfc_secret
                .ok_or_else(|| BackendError::Transport("missing NFC pairing secret".into()))?;
            Ok(nfc_secret.validate_response(&handshake_hash, secret))
        })
        .await
    }

    pub(super) async fn send_code_entry_tag(
        &mut self,
        code: String,
        handshake_hash: Vec<u8>,
        commitment: Option<Vec<u8>>,
        challenge: Option<Vec<u8>>,
        trezor_cpace_public_key: Option<Vec<u8>>,
    ) -> BackendResult<PairingTagResponse> {
        if code.len() != 6 {
            return Err(BackendError::Transport(
                "code entry must be 6 digits".into(),
            ));
        }
        let keys = CpaceHostKeys::generate(code.as_bytes(), &handshake_hash, &mut rand::rng());
        let trezor_key: [u8; 32] = trezor_cpace_public_key
            .as_deref()
            .and_then(|key| key.try_into().ok())
            .ok_or_else(|| BackendError::Transport("missing trezor cpace public key".into()))?;
        let message = messages::ThpCodeEntryCpaceHostTag {
            cpace_host_public_key: keys.public_key.to_vec(),
            tag: keys.shared_secret(&trezor_key).to_vec(),
        }
        .to_message();
        self.exchange_tag(message, |secret| {
            let commitment = commitment
                .ok_or_else(|| BackendError::Transport("missing handshake commitment".into()))?;
            let challenge = challenge
                .ok_or_else(|| BackendError::Transport("missing code entry challenge".into()))?;
            if let Err(err) =
                validate_code_entry_tag(&handshake_hash, &commitment, &challenge, &code, &secret)
            {
                debug!("code-entry validation failed: {err}");
                return Ok(PairingTagResponse::Retry("pairing code mismatch".into()));
            }
            Ok(PairingTagResponse::Accepted { secret })
        })
        .await
    }

    /// Sends a pairing tag and validates the device secret; a device Failure is a retryable mismatch.
    async fn exchange_tag(
        &mut self,
        message: EncodedMessage,
        validate: impl FnOnce(Vec<u8>) -> BackendResult<PairingTagResponse>,
    ) -> BackendResult<PairingTagResponse> {
        self.send(&message)?;
        let (message_type, payload) = self.receive_raw().await?;
        if message_type == MESSAGE_TYPE_FAILURE {
            let failure = BackendError::from_failure(&payload);
            return Ok(PairingTagResponse::Retry(failure.to_string()));
        }
        validate(ParsedTagResponse::decode(message_type, &payload)?.secret)
    }
}
