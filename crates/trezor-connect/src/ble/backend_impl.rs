use prost::Message;
use sha2::{Digest, Sha256};
use tracing::debug;
use trezor_thp::ChannelIO;

use super::bitcoin::{
    BitcoinTxRequestHandling, build_orig_txs_index, build_ref_txs_index, handle_bitcoin_tx_request,
};
use super::{
    BleBackend, MESSAGE_TYPE_CREATE_SESSION, MESSAGE_TYPE_FAILURE, MESSAGE_TYPE_SUCCESS,
    ThpChannel, decode_failure_as_backend_error, mapping_error,
};
use crate::thp::Chain;
use crate::thp::backend::{BackendError, BackendResult, ThpBackend};
use crate::thp::crypto::{
    get_cpace_host_keys, get_shared_secret, validate_code_entry_tag, validate_nfc_tag,
    validate_qr_code_tag,
};
use crate::thp::eip712::{build_struct_ack, resolve_value_for_member_path};
use crate::thp::messages;
use crate::thp::proto::{
    DecodedTypedDataResponse, ETH_DATA_CHUNK_SIZE, EncodedMessage, MESSAGE_TYPE_BITCOIN_TX_REQUEST,
    MESSAGE_TYPE_ETHEREUM_TX_REQUEST, MESSAGE_TYPE_SOLANA_TX_SIGNATURE, ParsedTagResponse,
    ProtoMappingError, decode_bitcoin_tx_request, decode_code_entry_cpace_response,
    decode_credential_response, decode_device_properties, decode_get_address_response,
    decode_get_nonce_response, decode_get_public_key_response, decode_pairing_request_approved,
    decode_select_method_response, decode_sign_message_response, decode_sign_typed_data_message,
    decode_sign_typed_data_response, decode_solana_tx_signature, decode_tag_response,
    decode_tx_request, encode_code_entry_challenge, encode_code_entry_tag,
    encode_credential_request, encode_end_request, encode_get_address_request,
    encode_get_nonce_request, encode_get_public_key_request, encode_nfc_tag,
    encode_pairing_request, encode_qr_tag, encode_select_method, encode_sign_message_request,
    encode_sign_tx_request, encode_sign_typed_data_request, encode_tx_ack,
    encode_typed_data_struct_ack, encode_typed_data_value_ack, to_pairing_tag_response,
};
use crate::thp::types::*;

const NFC_SECRET_LENGTH: usize = 16;
const NFC_HANDSHAKE_HASH_LENGTH: usize = 16;

fn build_nfc_data(
    secret: &[u8; NFC_SECRET_LENGTH],
    handshake_hash: &[u8],
) -> BackendResult<Vec<u8>> {
    let handshake_hash = handshake_hash
        .get(..NFC_HANDSHAKE_HASH_LENGTH)
        .ok_or_else(|| {
            BackendError::Transport(format!(
                "NFC pairing requires at least {NFC_HANDSHAKE_HASH_LENGTH} handshake hash bytes"
            ))
        })?;
    let mut data = Vec::with_capacity(NFC_SECRET_LENGTH + NFC_HANDSHAKE_HASH_LENGTH);
    data.extend_from_slice(secret);
    data.extend_from_slice(handshake_hash);
    Ok(data)
}

fn prepare_nfc_pairing(
    stored_secret: &mut Option<[u8; NFC_SECRET_LENGTH]>,
    secret: [u8; NFC_SECRET_LENGTH],
    handshake_hash: &[u8],
) -> BackendResult<Vec<u8>> {
    let nfc_data = build_nfc_data(&secret, handshake_hash)?;
    *stored_secret = Some(secret);
    Ok(nfc_data)
}

fn validated_nfc_pairing_response(
    handshake_hash: &[u8],
    secret: &[u8; NFC_SECRET_LENGTH],
    response_tag: Vec<u8>,
) -> PairingTagResponse {
    if let Err(err) = validate_nfc_tag(handshake_hash, &hex::encode(&response_tag), secret) {
        debug!("NFC tag validation failed: {err}");
        return PairingTagResponse::Retry("pairing tag mismatch".into());
    }

    PairingTagResponse::Accepted {
        secret: response_tag,
    }
}

fn record_bitcoin_signature(
    signatures: &mut Vec<Vec<u8>>,
    input_count: usize,
    signature_index: u32,
    signature: &[u8],
) -> BackendResult<()> {
    let invalid_index = || {
        BackendError::Device(format!(
            "device returned Bitcoin signature index {signature_index} for input count {input_count}"
        ))
    };
    let index = usize::try_from(signature_index).map_err(|_| invalid_index())?;
    if index >= input_count {
        return Err(invalid_index());
    }
    let required_len = index.checked_add(1).ok_or_else(invalid_index)?;
    if signatures.len() < required_len {
        signatures.resize(required_len, Vec::new());
    }
    signatures[index] = signature.to_vec();
    Ok(())
}

impl ThpBackend for BleBackend {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        self.reset_channel();
        self.allocate_channel(request.try_to_unlock).await?;
        let ThpChannel::Opening(open) = &mut self.channel else {
            return Err(BackendError::Transport(
                "THP channel allocation failed".into(),
            ));
        };
        let properties =
            decode_device_properties(open.device_properties()).map_err(mapping_error)?;
        if let (Ok(major), Ok(minor)) = (
            u8::try_from(properties.protocol_version_major),
            u8::try_from(properties.protocol_version_minor),
        ) {
            open.set_device_protocol_version(major, minor);
        }
        let channel = open.channel_id();
        debug!(
            "THP channel 0x{channel:04x}: methods={:?} protocol={}.{} model={}",
            properties.pairing_methods,
            properties.protocol_version_major,
            properties.protocol_version_minor,
            properties.internal_model,
        );
        Ok(CreateChannelResponse {
            channel,
            properties,
        })
    }

    async fn handshake(&mut self, request: HandshakeRequest) -> BackendResult<HandshakeResponse> {
        {
            let mut credentials = self.credentials.lock();
            credentials.static_key = request.static_key;
            credentials.known = request.known_credentials;
            credentials.selected = None;
        }
        let state = self.run_handshake().await?;
        Ok(HandshakeResponse {
            state,
            handshake_hash: self.handshake_hash()?,
            selected_credential: self.credentials.lock().selected.take(),
        })
    }

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        self.call(encode_pairing_request(&request), |message_type, payload| {
            if message_type != messages::ThpMessageType::ThpPairingRequestApproved as i32 as u16 {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            decode_pairing_request_approved(payload)
        })
        .await
    }

    async fn select_pairing_method(
        &mut self,
        request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        let mut response = self
            .call(encode_select_method(&request), |message_type, payload| {
                let message_type = messages::ThpMessageType::try_from(message_type as i32)
                    .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                decode_select_method_response(message_type, payload)
            })
            .await?;

        if request.method == PairingMethod::Nfc
            && let SelectMethodResponse::PairingPreparationsFinished { nfc_data } = &mut response
        {
            let handshake_hash = self.handshake_hash()?;
            let secret = rand::random::<[u8; NFC_SECRET_LENGTH]>();
            *nfc_data = Some(prepare_nfc_pairing(
                &mut self.nfc_secret,
                secret,
                &handshake_hash,
            )?);
        }
        Ok(response)
    }

    async fn code_entry_challenge(
        &mut self,
        request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        self.call(
            encode_code_entry_challenge(&request.challenge),
            |message_type, payload| {
                if message_type != messages::ThpMessageType::ThpCodeEntryCpaceTrezor as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_code_entry_cpace_response(payload)
            },
        )
        .await
    }

    async fn send_pairing_tag(
        &mut self,
        request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        match request {
            PairingTagRequest::QrCode {
                handshake_hash,
                tag,
            } => {
                let tag_bytes = hex::decode(&tag)
                    .map_err(|_| BackendError::Transport("invalid QR tag hex".into()))?;
                let mut hasher = Sha256::new();
                hasher.update(&handshake_hash);
                hasher.update(tag_bytes);
                let encoded =
                    encode_qr_tag(&hex::encode(hasher.finalize())).map_err(mapping_error)?;
                let response = match self.exchange_tag(encoded).await? {
                    Err(err) => return Ok(PairingTagResponse::Retry(err.to_string())),
                    Ok(response) => response,
                };
                if let Err(err) =
                    validate_qr_code_tag(&handshake_hash, &tag, &hex::encode(&response.secret))
                {
                    debug!("QR tag validation failed: {err}");
                    return Ok(PairingTagResponse::Retry("pairing tag mismatch".into()));
                }
                Ok(to_pairing_tag_response(response))
            }
            PairingTagRequest::Nfc {
                handshake_hash,
                tag,
            } => {
                let tag_bytes = hex::decode(&tag)
                    .map_err(|_| BackendError::Transport("invalid NFC tag hex".into()))?;
                let mut hasher = Sha256::new();
                hasher.update([messages::ThpPairingMethod::Nfc as u8]);
                hasher.update(&handshake_hash);
                hasher.update(&tag_bytes);
                let encoded =
                    encode_nfc_tag(&hex::encode(hasher.finalize())).map_err(mapping_error)?;
                let response = match self.exchange_tag(encoded).await? {
                    Err(err) => return Ok(PairingTagResponse::Retry(err.to_string())),
                    Ok(response) => response,
                };
                let secret = self
                    .nfc_secret
                    .as_ref()
                    .ok_or_else(|| BackendError::Transport("missing NFC pairing secret".into()))?;
                Ok(validated_nfc_pairing_response(
                    &handshake_hash,
                    secret,
                    response.secret,
                ))
            }
            PairingTagRequest::CodeEntry {
                code,
                handshake_hash,
                commitment,
                challenge,
                trezor_cpace_public_key,
            } => {
                if code.len() != 6 {
                    return Err(BackendError::Transport(
                        "code entry must be 6 digits".into(),
                    ));
                }
                let keys = get_cpace_host_keys(code.as_bytes(), &handshake_hash, &mut rand::rng());
                let trezor_key: [u8; 32] = trezor_cpace_public_key
                    .as_deref()
                    .and_then(|key| key.try_into().ok())
                    .ok_or_else(|| {
                        BackendError::Transport("missing trezor cpace public key".into())
                    })?;
                let shared_secret = get_shared_secret(&trezor_key, &keys.private_key);
                let encoded = encode_code_entry_tag(&keys.public_key, &shared_secret)
                    .map_err(mapping_error)?;
                let response = match self.exchange_tag(encoded).await? {
                    Err(err) => return Ok(PairingTagResponse::Retry(err.to_string())),
                    Ok(response) => response,
                };
                let commitment = commitment.ok_or_else(|| {
                    BackendError::Transport("missing handshake commitment".into())
                })?;
                let challenge = challenge.ok_or_else(|| {
                    BackendError::Transport("missing code entry challenge".into())
                })?;
                if let Err(err) = validate_code_entry_tag(
                    &handshake_hash,
                    &commitment,
                    &challenge,
                    &code,
                    &hex::encode(&response.secret),
                ) {
                    debug!("code-entry validation failed: {err}");
                    return Ok(PairingTagResponse::Retry("pairing code mismatch".into()));
                }
                Ok(to_pairing_tag_response(response))
            }
        }
    }

    async fn credential_request(
        &mut self,
        request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        self.call(
            encode_credential_request(&request),
            |message_type, payload| {
                if message_type != messages::ThpMessageType::ThpCredentialResponse as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_credential_response(payload)
            },
        )
        .await
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        self.call(encode_end_request(), |message_type, payload| {
            if message_type != messages::ThpMessageType::ThpEndResponse as i32 as u16 {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            messages::ThpEndResponse::decode(payload).map_err(ProtoMappingError::from)?;
            Ok(())
        })
        .await?;
        self.end_pairing()
    }

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        let payload = messages::ThpCreateNewSession {
            passphrase: request.passphrase,
            on_device: request.on_device.then_some(true),
            derive_cardano: request.derive_cardano.then_some(true),
        }
        .encode_to_vec();
        let message = EncodedMessage {
            message_type: MESSAGE_TYPE_CREATE_SESSION,
            payload,
        };
        self.call(Ok(message), |message_type, _| {
            if message_type != MESSAGE_TYPE_SUCCESS {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            Ok(CreateSessionResponse)
        })
        .await
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        let chain = request.chain;
        let mut response = self
            .call(
                encode_get_address_request(&request),
                |message_type, payload| decode_get_address_response(chain, message_type, payload),
            )
            .await?;
        if request.include_public_key {
            // Mirror Suite: keep GetPublicKey silent to avoid extra prompts.
            let public_key = self.get_public_key(chain, request.path).await?;
            response.public_key = Some(public_key);
        }
        Ok(response)
    }

    async fn get_public_key(&mut self, chain: Chain, path: Vec<u32>) -> BackendResult<String> {
        self.call(
            encode_get_public_key_request(chain, &path, false),
            |message_type, payload| decode_get_public_key_response(chain, message_type, payload),
        )
        .await
    }

    async fn get_nonce(&mut self) -> BackendResult<Vec<u8>> {
        self.call(encode_get_nonce_request(), decode_get_nonce_response)
            .await
    }

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        let chain = request.chain;
        self.call(
            encode_sign_message_request(&request),
            |message_type, payload| decode_sign_message_response(chain, message_type, payload),
        )
        .await
    }

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        let chain = request.chain;
        let encoded = encode_sign_typed_data_request(&request).map_err(mapping_error)?;
        let SignTypedDataPayload::TypedData(typed_data) = request.payload else {
            return self
                .call(Ok(encoded), |message_type, payload| {
                    decode_sign_typed_data_response(chain, message_type, payload)
                })
                .await;
        };
        let (mut message_type, mut payload) = self.request(encoded).await?;
        loop {
            let ack = match decode_sign_typed_data_message(chain, message_type, &payload)
                .map_err(mapping_error)?
            {
                DecodedTypedDataResponse::Signature(response) => return Ok(response),
                DecodedTypedDataResponse::StructRequest(struct_request) => {
                    let ack = build_struct_ack(&typed_data, &struct_request.name)?;
                    encode_typed_data_struct_ack(&ack)
                }
                DecodedTypedDataResponse::ValueRequest(value_request) => {
                    let value =
                        resolve_value_for_member_path(&typed_data, &value_request.member_path)?;
                    encode_typed_data_value_ack(value)
                }
            };
            (message_type, payload) = self.request(ack.map_err(mapping_error)?).await?;
        }
    }

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
        let (encoded, initial_chunk_len) =
            encode_sign_tx_request(&request).map_err(mapping_error)?;
        let (message_type, payload) = self.request(encoded).await?;
        match request.chain {
            Chain::Ethereum => {
                self.sign_ethereum_tx(&request.data, initial_chunk_len, message_type, payload)
                    .await
            }
            Chain::Solana => {
                if message_type != MESSAGE_TYPE_SOLANA_TX_SIGNATURE {
                    return Err(unexpected_signing_message(message_type, "Solana"));
                }
                let signature =
                    decode_solana_tx_signature(message_type, &payload).map_err(mapping_error)?;
                Ok(SignTxResponse {
                    chain: Chain::Solana,
                    v: 0,
                    r: signature,
                    s: Vec::new(),
                    signatures: Vec::new(),
                })
            }
            Chain::Bitcoin => {
                let btc = request.btc.as_ref().ok_or_else(|| {
                    BackendError::Transport("missing Bitcoin signing payload".into())
                })?;
                self.sign_bitcoin_tx(btc, message_type, payload).await
            }
        }
    }

    async fn abort(&mut self) -> BackendResult<()> {
        self.reset_channel();
        self.link
            .disconnect()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))
    }
}

fn unexpected_signing_message(message_type: u16, chain: &str) -> BackendError {
    BackendError::Transport(format!(
        "unexpected message type {message_type} during {chain} sign_tx"
    ))
}

impl BleBackend {
    /// Pairing tags treat a device Failure as a retryable mismatch rather than an error.
    async fn exchange_tag(
        &mut self,
        message: EncodedMessage,
    ) -> BackendResult<Result<ParsedTagResponse, BackendError>> {
        self.send(&message)?;
        let (message_type, payload) = self.receive_raw().await?;
        if message_type == MESSAGE_TYPE_FAILURE {
            return Ok(Err(decode_failure_as_backend_error(&payload)));
        }
        let message_type = messages::ThpMessageType::try_from(message_type as i32)
            .map_err(|_| mapping_error(ProtoMappingError::UnexpectedMessage(message_type)))?;
        decode_tag_response(message_type, &payload)
            .map(Ok)
            .map_err(mapping_error)
    }

    async fn sign_ethereum_tx(
        &mut self,
        data: &[u8],
        mut data_offset: usize,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTxResponse> {
        loop {
            if message_type != MESSAGE_TYPE_ETHEREUM_TX_REQUEST {
                return Err(unexpected_signing_message(message_type, "Ethereum"));
            }
            let tx_request = decode_tx_request(message_type, &payload).map_err(mapping_error)?;
            if let (Some(v), Some(r), Some(s)) = (
                tx_request.signature_v,
                tx_request.signature_r,
                tx_request.signature_s,
            ) {
                return Ok(SignTxResponse {
                    chain: Chain::Ethereum,
                    v,
                    r,
                    s,
                    signatures: Vec::new(),
                });
            }
            let Some(requested_len) = tx_request.data_length else {
                return Err(BackendError::Transport(
                    "EthereumTxRequest has neither signature nor data_length".into(),
                ));
            };
            let requested_len = requested_len as usize;
            if requested_len > 0 && data_offset >= data.len() {
                return Err(BackendError::Transport(
                    "device requested additional tx data beyond payload length".into(),
                ));
            }
            let end = (data_offset + requested_len.min(ETH_DATA_CHUNK_SIZE)).min(data.len());
            let ack = encode_tx_ack(&data[data_offset..end]).map_err(mapping_error)?;
            data_offset = end;
            (message_type, payload) = self.request(ack).await?;
        }
    }

    async fn sign_bitcoin_tx(
        &mut self,
        btc: &BtcSignTx,
        mut message_type: u16,
        mut payload: Vec<u8>,
    ) -> BackendResult<SignTxResponse> {
        let ref_txs_by_hash = build_ref_txs_index(btc);
        let orig_txs_by_hash = build_orig_txs_index(btc);
        let mut signatures: Vec<Vec<u8>> = Vec::new();
        let mut last_signature: Option<Vec<u8>> = None;

        loop {
            if message_type != MESSAGE_TYPE_BITCOIN_TX_REQUEST {
                return Err(unexpected_signing_message(message_type, "Bitcoin"));
            }
            let tx_request =
                decode_bitcoin_tx_request(message_type, &payload).map_err(mapping_error)?;
            if let Some(signature) = tx_request.signature.as_ref() {
                last_signature = Some(signature.clone());
                if let Some(index) = tx_request.signature_index {
                    record_bitcoin_signature(&mut signatures, btc.inputs.len(), index, signature)?;
                }
            }
            (message_type, payload) = match handle_bitcoin_tx_request(
                btc,
                &ref_txs_by_hash,
                &orig_txs_by_hash,
                &tx_request,
            )? {
                BitcoinTxRequestHandling::Ack(ack) => self.request(ack).await?,
                BitcoinTxRequestHandling::Continue => self.receive().await?,
                BitcoinTxRequestHandling::Finished => {
                    // Legacy fallback: prefer last indexed signature for 'r'.
                    let r = signatures
                        .last()
                        .cloned()
                        .or(last_signature)
                        .unwrap_or_default();
                    return Ok(SignTxResponse {
                        chain: Chain::Bitcoin,
                        v: 0,
                        r,
                        s: Vec::new(),
                        signatures,
                    });
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nfc_response_tag(handshake_hash: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update([messages::ThpPairingMethod::Nfc as u8]);
        hasher.update(handshake_hash);
        hasher.update(secret);
        hasher.finalize()[..NFC_HANDSHAKE_HASH_LENGTH].to_vec()
    }

    #[test]
    fn nfc_pairing_data_and_response_match_suite_layout() {
        let handshake_hash = [0x21; 32];
        let secret = [0x34; NFC_SECRET_LENGTH];
        let mut stored_secret = None;
        let nfc_data = prepare_nfc_pairing(&mut stored_secret, secret, &handshake_hash).unwrap();

        assert_eq!(stored_secret, Some(secret));
        assert_eq!(&nfc_data[..NFC_SECRET_LENGTH], &secret);
        assert_eq!(
            &nfc_data[NFC_SECRET_LENGTH..],
            &handshake_hash[..NFC_HANDSHAKE_HASH_LENGTH]
        );

        let response_tag = nfc_response_tag(&handshake_hash, &secret);
        assert!(matches!(
            validated_nfc_pairing_response(&handshake_hash, &secret, response_tag),
            PairingTagResponse::Accepted { .. }
        ));
    }

    #[test]
    fn nfc_pairing_preparations_replace_previous_secret() {
        let handshake_hash = [0x21; 32];
        let old_secret = [0x34; NFC_SECRET_LENGTH];
        let new_secret = [0x56; NFC_SECRET_LENGTH];
        let mut stored_secret = Some(old_secret);

        let nfc_data =
            prepare_nfc_pairing(&mut stored_secret, new_secret, &handshake_hash).unwrap();

        assert_eq!(stored_secret, Some(new_secret));
        assert_eq!(&nfc_data[..NFC_SECRET_LENGTH], &new_secret);
    }

    #[test]
    fn nfc_pairing_retries_mismatched_device_tag() {
        let handshake_hash = [0x21; 32];
        let secret = [0x34; NFC_SECRET_LENGTH];
        let response = validated_nfc_pairing_response(&handshake_hash, &secret, vec![0; 16]);

        assert!(matches!(response, PairingTagResponse::Retry(_)));
    }

    #[test]
    fn bitcoin_signature_index_accepts_last_input() {
        let mut signatures = Vec::new();

        record_bitcoin_signature(&mut signatures, 2, 1, &[0xaa, 0xbb]).unwrap();

        assert_eq!(signatures, vec![Vec::<u8>::new(), vec![0xaa, 0xbb]]);
    }

    #[test]
    fn bitcoin_signature_index_rejects_out_of_range_without_resizing() {
        for signature_index in [1, u32::MAX] {
            let mut signatures = vec![vec![0x11]];
            let err = record_bitcoin_signature(&mut signatures, 1, signature_index, &[0xaa, 0xbb])
                .unwrap_err();

            let BackendError::Device(message) = err else {
                panic!("expected device error");
            };
            assert_eq!(
                message,
                format!(
                    "device returned Bitcoin signature index {signature_index} for input count 1"
                )
            );
            assert_eq!(signatures, vec![vec![0x11]]);
        }
    }
}
