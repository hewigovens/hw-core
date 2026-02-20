use super::*;

impl ThpBackend for BleBackend {
    async fn create_channel(
        &mut self,
        request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        debug!(
            "THP create_channel start: nonce={}",
            hex::encode(request.nonce)
        );
        let frame = wire::encode_create_channel_request(&request.nonce);
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_CREATE_CHANNEL_REQUEST);

        let parsed = self.read_next().await?;
        let response = match parsed.response {
            WireResponse::CreateChannel {
                nonce,
                channel,
                properties,
                handshake_hash,
            } => {
                if nonce != request.nonce {
                    return Err(BackendError::Transport(
                        "nonce mismatch in THP create channel".into(),
                    ));
                }
                self.state.on_receive(parsed.header.magic);
                self.state.set_channel(channel);
                self.state.set_handshake_hash(handshake_hash);
                debug!(
                    "THP create_channel ok: channel=0x{:04x} methods={:?} protocol={}.{} model={} variant={}",
                    channel,
                    properties.pairing_methods,
                    properties.protocol_version_major,
                    properties.protocol_version_minor,
                    properties.internal_model,
                    properties.model_variant
                );
                CreateChannelResponse {
                    nonce,
                    channel,
                    handshake_hash: handshake_hash.to_vec(),
                    properties,
                }
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )));
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to create_channel: {:?}",
                    other
                )));
            }
        };

        Ok(response)
    }

    async fn handshake_init(
        &mut self,
        request: HandshakeInitRequest,
    ) -> BackendResult<HandshakeInitOutcome> {
        let handshake_hash = self
            .state
            .handshake_hash()
            .ok_or_else(|| BackendError::Transport("missing handshake hash".into()))?;

        let mut rng = StdRng::from_rng(&mut rand::rng());

        let (host_static_private, host_static_public, host_static_vec) =
            if let Some(ref key) = request.static_key {
                let array = self.to_array::<32>(key)?;
                let public = derive_public_from_private(&array);
                (array, public, key.clone())
            } else {
                let Curve25519KeyPair {
                    private_key,
                    public_key,
                } = get_curve25519_key_pair(&mut rng);
                (private_key, public_key, private_key.to_vec())
            };

        let Curve25519KeyPair {
            private_key: host_ephemeral_private,
            public_key: host_ephemeral_public,
        } = get_curve25519_key_pair(&mut rng);

        let frame = wire::encode_handshake_init_request(
            self.state.channel(),
            self.state.send_bit(),
            &host_ephemeral_public,
            request.try_to_unlock,
        );
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_HANDSHAKE_INIT_REQUEST);

        let parsed = self.read_next().await?;
        let (trezor_ephemeral_pubkey, trezor_encrypted_static_pubkey, tag) = match parsed.response {
            WireResponse::HandshakeInit {
                trezor_ephemeral_pubkey,
                trezor_encrypted_static_pubkey,
                tag,
            } => {
                self.state.on_receive(parsed.header.magic);
                self.state.set_expected_responses(&[]);
                (trezor_ephemeral_pubkey, trezor_encrypted_static_pubkey, tag)
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )));
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to handshake init: {:?}",
                    other
                )));
            }
        };

        let encode_handshake_payload = |credential: Option<&str>| -> Vec<u8> {
            let host_pairing_credential = credential.and_then(|c| hex::decode(c).ok());
            let message = messages::ThpHandshakeCompletionReqNoisePayload {
                host_pairing_credential,
            };
            let mut buf = Vec::new();
            message.encode(&mut buf).expect("encode handshake payload");
            buf
        };

        let handshake_response = HandshakeInitResponse {
            trezor_ephemeral_pubkey,
            trezor_encrypted_static_pubkey: &trezor_encrypted_static_pubkey,
            tag,
        };

        let handshake_result = handle_handshake_init(HandshakeInitInput {
            handshake_hash,
            send_nonce: self.state.send_nonce(),
            recv_nonce: self.state.recv_nonce(),
            host_static_private,
            host_static_public,
            host_ephemeral_private,
            host_ephemeral_public,
            try_to_unlock: request.try_to_unlock,
            known_credentials: &request.known_credentials,
            response: handshake_response,
            encode_handshake_payload: &encode_handshake_payload,
        })
        .map_err(Self::transport_error)?;

        self.state
            .set_keys(handshake_result.host_key, handshake_result.trezor_key);
        self.state
            .set_handshake_hash(handshake_result.handshake_hash);

        let outcome = HandshakeInitOutcome {
            host_encrypted_static_pubkey: handshake_result.host_encrypted_static_pubkey,
            encrypted_payload: handshake_result.encrypted_payload,
            trezor_encrypted_static_pubkey: handshake_result.trezor_encrypted_static_pubkey,
            handshake_hash: handshake_result.handshake_hash.to_vec(),
            host_key: handshake_result.host_key.to_vec(),
            trezor_key: handshake_result.trezor_key.to_vec(),
            host_static_key: host_static_vec,
            host_static_public_key: host_static_public.to_vec(),
            pairing_methods: request.pairing_methods,
            credentials: handshake_result.credentials.clone(),
            selected_credential: handshake_result.selected_credential.clone(),
            nfc_data: None,
            handshake_commitment: None,
            trezor_cpace_public_key: None,
            code_entry_challenge: None,
        };

        Ok(outcome)
    }

    async fn handshake_complete(
        &mut self,
        request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse> {
        let frame = wire::encode_handshake_completion_request(
            self.state.channel(),
            self.state.send_bit(),
            &request.host_pubkey,
            &request.encrypted_payload,
        );
        self.send_frame(frame).await?;
        self.state.on_send(MAGIC_HANDSHAKE_COMPLETION_REQUEST);

        let parsed = self.read_next().await?;
        let state = match parsed.response {
            WireResponse::HandshakeCompletion {
                encrypted_state,
                tag,
            } => {
                self.state.on_receive(parsed.header.magic);
                self.state.set_expected_responses(&[]);

                // Handshake completion response is AES-GCM encrypted with key_response,
                // nonce 0, empty associated data and a single-byte plaintext state.
                let key = self.trezor_key()?;
                let iv = [0u8; 12];
                let plaintext = aes256gcm_decrypt(&key, &iv, &[], &[encrypted_state], &tag)
                    .map_err(|_| {
                        BackendError::Transport(
                            "failed to decrypt handshake completion state".into(),
                        )
                    })?;
                if plaintext.len() != 1 {
                    return Err(BackendError::Transport(format!(
                        "invalid decrypted handshake completion state length {}",
                        plaintext.len()
                    )));
                }
                plaintext[0]
            }
            WireResponse::Error(code) => {
                return Err(BackendError::Device(format!(
                    "device returned error code {code}"
                )));
            }
            other => {
                return Err(BackendError::Transport(format!(
                    "unexpected response to handshake completion: {:?}",
                    other
                )));
            }
        };

        let completion_state = match state {
            0 => HandshakeCompletionState::RequiresPairing,
            1 => HandshakeCompletionState::Paired,
            2 => HandshakeCompletionState::AutoPaired,
            other => {
                return Err(BackendError::Transport(format!(
                    "unknown handshake completion state {other}"
                )));
            }
        };

        Ok(HandshakeCompletionResponse {
            state: completion_state,
        })
    }

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        let encoded = encode_pairing_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type != messages::ThpMessageType::ThpPairingRequestApproved as i32 as u16
                {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_pairing_request_approved(payload)
            })
            .await?;

        Ok(response)
    }

    async fn select_pairing_method(
        &mut self,
        request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        let encoded = encode_select_method(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let outcome: ResponseOrReason<SelectMethodResponse> = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type == MESSAGE_TYPE_FAILURE {
                    return Ok(Err(decode_failure_reason(payload)));
                }
                let message_type_enum = messages::ThpMessageType::try_from(message_type as i32)
                    .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                let response = decode_select_method_response(message_type_enum, payload)?;
                Ok(Ok(response))
            })
            .await?;
        let response = match outcome {
            Ok(response) => response,
            Err(reason) => return Err(BackendError::Device(reason)),
        };

        Ok(response)
    }

    async fn code_entry_challenge(
        &mut self,
        request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        debug!(
            "BLE THP TX code-entry challenge payload_len={}",
            request.challenge.len()
        );
        let encoded =
            encode_code_entry_challenge(&request.challenge).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let outcome: ResponseOrReason<CodeEntryChallengeResponse> = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type == MESSAGE_TYPE_FAILURE {
                    return Ok(Err(decode_failure_reason(payload)));
                }
                if message_type != messages::ThpMessageType::ThpCodeEntryCpaceTrezor as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                let response = decode_code_entry_cpace_response(payload)?;
                Ok(Ok(response))
            })
            .await?;
        let response = match outcome {
            Ok(response) => response,
            Err(reason) => {
                return Err(BackendError::Device(reason));
            }
        };
        debug!(
            "BLE THP RX code-entry cpace public_key_len={}",
            response.trezor_cpace_public_key.len()
        );

        Ok(response)
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
                let hashed = hasher.finalize();
                let hashed_hex = hex::encode(hashed);

                let encoded = encode_qr_tag(&hashed_hex).map_err(Self::transport_error)?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let outcome: ResponseOrReason<crate::thp::proto::ParsedTagResponse> = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        if message_type == MESSAGE_TYPE_FAILURE {
                            return Ok(Err(decode_failure_reason(payload)));
                        }
                        let message_type_enum =
                            messages::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        let parsed = decode_tag_response(message_type_enum, payload)?;
                        Ok(Ok(parsed))
                    })
                    .await?;

                let response = match outcome {
                    Err(reason) => return Ok(PairingTagResponse::Retry(reason)),
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
                let hashed = hasher.finalize();
                let hashed_hex = hex::encode(hashed);

                let encoded = encode_nfc_tag(&hashed_hex).map_err(Self::transport_error)?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let outcome: ResponseOrReason<crate::thp::proto::ParsedTagResponse> = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        if message_type == MESSAGE_TYPE_FAILURE {
                            return Ok(Err(decode_failure_reason(payload)));
                        }
                        let message_type_enum =
                            messages::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        let parsed = decode_tag_response(message_type_enum, payload)?;
                        Ok(Ok(parsed))
                    })
                    .await?;

                let response = match outcome {
                    Err(reason) => return Ok(PairingTagResponse::Retry(reason)),
                    Ok(response) => response,
                };

                // Validation requires stored NFC secret; not available here, so defer to workflow.
                Ok(to_pairing_tag_response(response))
            }
            PairingTagRequest::CodeEntry {
                code,
                handshake_hash,
                commitment,
                challenge,
                trezor_cpace_public_key,
                ..
            } => {
                if code.len() != 6 {
                    return Err(BackendError::Transport(
                        "code entry must be 6 digits".into(),
                    ));
                }

                let mut rng = StdRng::from_rng(&mut rand::rng());
                let keys = get_cpace_host_keys(code.as_bytes(), &handshake_hash, &mut rng);
                let trezor_key = trezor_cpace_public_key.as_ref().ok_or_else(|| {
                    BackendError::Transport("missing trezor cpace public key".into())
                })?;
                let trezor_key = self.to_array::<32>(trezor_key)?;
                let shared_secret = get_shared_secret(&trezor_key, &keys.private_key);

                let encoded = encode_code_entry_tag(&keys.public_key, &shared_secret)
                    .map_err(Self::transport_error)?;
                self.send_encrypted_request(encoded).await?;

                let parsed = self.read_next().await?;
                let outcome: ResponseOrReason<crate::thp::proto::ParsedTagResponse> = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        if message_type == MESSAGE_TYPE_FAILURE {
                            return Ok(Err(decode_failure_reason(payload)));
                        }
                        let message_type_enum =
                            messages::ThpMessageType::try_from(message_type as i32)
                                .map_err(|_| ProtoMappingError::UnexpectedMessage(message_type))?;
                        let parsed = decode_tag_response(message_type_enum, payload)?;
                        Ok(Ok(parsed))
                    })
                    .await?;

                let response = match outcome {
                    Err(reason) => return Ok(PairingTagResponse::Retry(reason)),
                    Ok(response) => response,
                };

                if let Err(err) = validate_code_entry_tag(
                    &handshake_hash,
                    commitment.as_ref().ok_or_else(|| {
                        BackendError::Transport("missing handshake commitment".into())
                    })?,
                    challenge.as_ref().ok_or_else(|| {
                        BackendError::Transport("missing code entry challenge".into())
                    })?,
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
        let encoded = encode_credential_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type != messages::ThpMessageType::ThpCredentialResponse as i32 as u16 {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                decode_credential_response(payload)
            })
            .await?;

        Ok(response)
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        let encoded = encode_end_request().map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        self.parse_encrypted_response(parsed, |message_type, payload| {
            if message_type != messages::ThpMessageType::ThpEndResponse as i32 as u16 {
                return Err(ProtoMappingError::UnexpectedMessage(message_type));
            }
            messages::ThpEndResponse::decode(payload).map_err(ProtoMappingError::from)?;
            Ok(())
        })
        .await?;

        Ok(())
    }

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        let message = messages::ThpCreateNewSession {
            passphrase: request.passphrase.clone(),
            on_device: request.on_device.then_some(true),
            derive_cardano: request.derive_cardano.then_some(true),
        };

        let mut payload = Vec::new();
        message
            .encode(&mut payload)
            .map_err(|e| BackendError::Transport(e.to_string()))?;

        let encoded = EncodedMessage {
            message_type: MESSAGE_TYPE_CREATE_SESSION,
            payload,
        };
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let outcome: ResponseOrReason<()> = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type == MESSAGE_TYPE_FAILURE {
                    return Ok(Err(decode_failure_reason(payload)));
                }
                if message_type != MESSAGE_TYPE_SUCCESS {
                    return Err(ProtoMappingError::UnexpectedMessage(message_type));
                }
                Ok(Ok(()))
            })
            .await?;
        if let Err(reason) = outcome {
            return Err(BackendError::Device(reason));
        }

        Ok(CreateSessionResponse)
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        let encoded = encode_get_address_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response_or_reason: ResponseOrReason<GetAddressResponse> = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type == MESSAGE_TYPE_FAILURE {
                    return Ok(Err(decode_failure_reason(payload)));
                }
                let response = decode_get_address_response(request.chain, message_type, payload)?;
                Ok(Ok(response))
            })
            .await?;
        let mut response = match response_or_reason {
            Ok(response) => response,
            Err(reason) => return Err(BackendError::Device(reason)),
        };

        if request.include_public_key {
            // Keep public-key retrieval silent. Address confirmation is handled by GetAddress
            // itself; mirroring Suite behavior avoids extra on-device prompts/failures.
            let encoded = encode_get_public_key_request(request.chain, &request.path, false)
                .map_err(Self::transport_error)?;
            self.send_encrypted_request(encoded).await?;

            let parsed = self.read_next().await?;
            let public_key_or_reason: ResponseOrReason<String> = self
                .parse_encrypted_response(parsed, |message_type, payload| {
                    if message_type == MESSAGE_TYPE_FAILURE {
                        return Ok(Err(decode_failure_reason(payload)));
                    }
                    let public_key =
                        decode_get_public_key_response(request.chain, message_type, payload)?;
                    Ok(Ok(public_key))
                })
                .await?;
            let public_key = match public_key_or_reason {
                Ok(public_key) => public_key,
                Err(reason) => return Err(BackendError::Device(reason)),
            };
            response.public_key = Some(public_key);
        }

        Ok(response)
    }

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        let encoded = encode_sign_message_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        let parsed = self.read_next().await?;
        let response_or_reason: ResponseOrReason<SignMessageResponse> = self
            .parse_encrypted_response(parsed, |message_type, payload| {
                if message_type == MESSAGE_TYPE_FAILURE {
                    return Ok(Err(decode_failure_reason(payload)));
                }
                let response = decode_sign_message_response(request.chain, message_type, payload)?;
                Ok(Ok(response))
            })
            .await?;

        match response_or_reason {
            Ok(response) => Ok(response),
            Err(reason) => Err(BackendError::Device(reason)),
        }
    }

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        let chain = request.chain;
        let payload_kind = request.payload.clone();
        let encoded = encode_sign_typed_data_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;

        match payload_kind {
            SignTypedDataPayload::Hashes { .. } => {
                let parsed = self.read_next().await?;
                let response_or_reason: ResponseOrReason<SignTypedDataResponse> = self
                    .parse_encrypted_response(parsed, |message_type, payload| {
                        if message_type == MESSAGE_TYPE_FAILURE {
                            return Ok(Err(decode_failure_reason(payload)));
                        }
                        let response =
                            decode_sign_typed_data_response(chain, message_type, payload)?;
                        Ok(Ok(response))
                    })
                    .await?;
                match response_or_reason {
                    Ok(response) => Ok(response),
                    Err(reason) => Err(BackendError::Device(reason)),
                }
            }
            SignTypedDataPayload::TypedData(typed_data) => loop {
                let parsed = self.read_next().await?;
                if self.should_ack(&parsed.header) {
                    self.send_ack(&parsed.header).await?;
                }

                let (message_type, payload) = match parsed.response {
                    WireResponse::Protobuf { payload } => {
                        let result = self.decrypt_device_message(&payload)?;
                        self.state.on_receive(parsed.header.magic);
                        result
                    }
                    WireResponse::Error(code) => {
                        return Err(BackendError::Device(format!(
                            "device returned error code {code}"
                        )));
                    }
                    other => {
                        return Err(BackendError::Transport(format!(
                            "unexpected response type {:?}",
                            other
                        )));
                    }
                };

                debug!(
                    "BLE THP sign_typed_data RX message_type={} ({}) payload_len={}",
                    message_type,
                    thp_message_name(message_type),
                    payload.len()
                );

                if message_type == MESSAGE_TYPE_BUTTON_REQUEST {
                    debug!("BLE THP sign_typed_data: ButtonRequest; sending ButtonAck");
                    self.send_button_ack().await?;
                    continue;
                }

                if message_type == MESSAGE_TYPE_FAILURE {
                    return Err(BackendError::Device(decode_failure_reason(&payload)));
                }

                match decode_sign_typed_data_message(chain, message_type, &payload)
                    .map_err(Self::transport_error)?
                {
                    DecodedTypedDataResponse::Signature(response) => {
                        self.state.set_expected_responses(&[]);
                        return Ok(response);
                    }
                    DecodedTypedDataResponse::StructRequest(struct_request) => {
                        let ack = build_struct_ack(&typed_data, &struct_request.name)?;
                        let encoded_ack =
                            encode_typed_data_struct_ack(&ack).map_err(Self::transport_error)?;
                        self.send_encrypted_request(encoded_ack).await?;
                    }
                    DecodedTypedDataResponse::ValueRequest(value_request) => {
                        let value =
                            resolve_value_for_member_path(&typed_data, &value_request.member_path)?;
                        let encoded_ack =
                            encode_typed_data_value_ack(value).map_err(Self::transport_error)?;
                        self.send_encrypted_request(encoded_ack).await?;
                    }
                }
            },
        }
    }

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
        let chain = request.chain;
        let (encoded, initial_chunk_len) =
            encode_sign_tx_request(&request).map_err(Self::transport_error)?;
        self.send_encrypted_request(encoded).await?;
        match chain {
            Chain::Ethereum => {
                let full_data = request.data.clone();
                let mut data_offset = initial_chunk_len;

                loop {
                    let parsed = self.read_next().await?;
                    if self.should_ack(&parsed.header) {
                        self.send_ack(&parsed.header).await?;
                    }

                    let (message_type, payload) = match parsed.response {
                        WireResponse::Protobuf { payload } => {
                            let result = self.decrypt_device_message(&payload)?;
                            self.state.on_receive(parsed.header.magic);
                            result
                        }
                        WireResponse::Error(code) => {
                            return Err(BackendError::Device(format!(
                                "device returned error code {code}"
                            )));
                        }
                        other => {
                            return Err(BackendError::Transport(format!(
                                "unexpected response type {:?}",
                                other
                            )));
                        }
                    };

                    debug!(
                        "BLE THP sign_tx RX message_type={} ({}) payload_len={}",
                        message_type,
                        thp_message_name(message_type),
                        payload.len()
                    );

                    if message_type == MESSAGE_TYPE_BUTTON_REQUEST {
                        debug!("BLE THP sign_tx: ButtonRequest; sending ButtonAck");
                        self.send_button_ack().await?;
                        continue;
                    }

                    if message_type == MESSAGE_TYPE_FAILURE {
                        return Err(BackendError::Device(decode_failure_reason(&payload)));
                    }

                    if message_type != MESSAGE_TYPE_ETHEREUM_TX_REQUEST {
                        return Err(BackendError::Transport(format!(
                            "unexpected message type {} during Ethereum sign_tx",
                            message_type
                        )));
                    }

                    let tx_request =
                        decode_tx_request(message_type, &payload).map_err(Self::transport_error)?;
                    if let (Some(v), Some(r), Some(s)) = (
                        tx_request.signature_v,
                        tx_request.signature_r,
                        tx_request.signature_s,
                    ) {
                        self.state.set_expected_responses(&[]);
                        return Ok(SignTxResponse { chain, v, r, s });
                    }

                    if let Some(requested_len) = tx_request.data_length {
                        let requested_len = requested_len as usize;
                        if requested_len > 0 && data_offset >= full_data.len() {
                            return Err(BackendError::Transport(
                                "device requested additional tx data beyond payload length".into(),
                            ));
                        }

                        let chunk_len = requested_len.min(ETH_DATA_CHUNK_SIZE);
                        let end = (data_offset + chunk_len).min(full_data.len());
                        let chunk = &full_data[data_offset..end];
                        data_offset = end;

                        let encoded_ack = encode_tx_ack(chunk).map_err(Self::transport_error)?;
                        self.send_encrypted_request(encoded_ack).await?;
                        continue;
                    }

                    return Err(BackendError::Transport(
                        "EthereumTxRequest has neither signature nor data_length".into(),
                    ));
                }
            }
            Chain::Solana => loop {
                let parsed = self.read_next().await?;
                if self.should_ack(&parsed.header) {
                    self.send_ack(&parsed.header).await?;
                }

                let (message_type, payload) = match parsed.response {
                    WireResponse::Protobuf { payload } => {
                        let result = self.decrypt_device_message(&payload)?;
                        self.state.on_receive(parsed.header.magic);
                        result
                    }
                    WireResponse::Error(code) => {
                        return Err(BackendError::Device(format!(
                            "device returned error code {code}"
                        )));
                    }
                    other => {
                        return Err(BackendError::Transport(format!(
                            "unexpected response type {:?}",
                            other
                        )));
                    }
                };

                debug!(
                    "BLE THP sign_tx RX message_type={} ({}) payload_len={}",
                    message_type,
                    thp_message_name(message_type),
                    payload.len()
                );

                if message_type == MESSAGE_TYPE_BUTTON_REQUEST {
                    debug!("BLE THP sign_tx: ButtonRequest; sending ButtonAck");
                    self.send_button_ack().await?;
                    continue;
                }

                if message_type == MESSAGE_TYPE_FAILURE {
                    return Err(BackendError::Device(decode_failure_reason(&payload)));
                }

                if message_type != MESSAGE_TYPE_SOLANA_TX_SIGNATURE {
                    return Err(BackendError::Transport(format!(
                        "unexpected message type {} during Solana sign_tx",
                        message_type
                    )));
                }

                let signature = decode_solana_tx_signature(message_type, &payload)
                    .map_err(Self::transport_error)?;
                self.state.set_expected_responses(&[]);
                return Ok(SignTxResponse {
                    chain,
                    v: 0,
                    r: signature,
                    s: Vec::new(),
                });
            },
            Chain::Bitcoin => {
                let btc = request.btc.clone().ok_or_else(|| {
                    BackendError::Transport("missing Bitcoin signing payload".into())
                })?;
                let ref_txs_by_hash = build_ref_txs_index(&btc);
                let mut latest_signature: Option<Vec<u8>> = None;

                loop {
                    let parsed = self.read_next().await?;
                    if self.should_ack(&parsed.header) {
                        self.send_ack(&parsed.header).await?;
                    }

                    let (message_type, payload) = match parsed.response {
                        WireResponse::Protobuf { payload } => {
                            let result = self.decrypt_device_message(&payload)?;
                            self.state.on_receive(parsed.header.magic);
                            result
                        }
                        WireResponse::Error(code) => {
                            return Err(BackendError::Device(format!(
                                "device returned error code {code}"
                            )));
                        }
                        other => {
                            return Err(BackendError::Transport(format!(
                                "unexpected response type {:?}",
                                other
                            )));
                        }
                    };

                    debug!(
                        "BLE THP sign_tx RX message_type={} ({}) payload_len={}",
                        message_type,
                        thp_message_name(message_type),
                        payload.len()
                    );

                    if message_type == MESSAGE_TYPE_BUTTON_REQUEST {
                        debug!("BLE THP sign_tx: ButtonRequest; sending ButtonAck");
                        self.send_button_ack().await?;
                        continue;
                    }

                    if message_type == MESSAGE_TYPE_FAILURE {
                        return Err(BackendError::Device(decode_failure_reason(&payload)));
                    }

                    if message_type != MESSAGE_TYPE_BITCOIN_TX_REQUEST {
                        return Err(BackendError::Transport(format!(
                            "unexpected message type {} during Bitcoin sign_tx",
                            message_type
                        )));
                    }

                    let tx_request = decode_bitcoin_tx_request(message_type, &payload)
                        .map_err(Self::transport_error)?;
                    if let Some(signature) = tx_request.signature.as_ref() {
                        latest_signature = Some(signature.clone());
                    }

                    match handle_bitcoin_tx_request(&btc, &ref_txs_by_hash, &tx_request)? {
                        BitcoinTxRequestHandling::Ack(ack) => {
                            self.send_encrypted_request(ack).await?;
                        }
                        BitcoinTxRequestHandling::Finished => {
                            self.state.set_expected_responses(&[]);
                            return Ok(SignTxResponse {
                                chain,
                                v: 0,
                                r: latest_signature.unwrap_or_default(),
                                s: Vec::new(),
                            });
                        }
                        BitcoinTxRequestHandling::Continue => {
                            // Some responses carry only serialized/signature progress.
                            continue;
                        }
                    }
                }
            }
        }
    }

    async fn abort(&mut self) -> BackendResult<()> {
        self.transport.reset();
        self.inner
            .abort()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))
    }
}
