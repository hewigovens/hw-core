use tracing::debug;
use trezor_thp::ChannelIO;

use super::backend::BleBackend;
use super::channel::ThpChannel;
use crate::thp::Chain;
use crate::thp::backend::{BackendError, BackendResult, ThpBackend};
use crate::thp::messages;
use crate::thp::proto::{GetNonce, Nonce, WireMessage};
use crate::thp::types::*;

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
        let properties = ThpProperties::decode(open.device_properties())?;
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
        self.credentials
            .prepare(request.static_key, request.known_credentials);
        let state = self.run_handshake().await?;
        Ok(HandshakeResponse {
            state,
            handshake_hash: self.handshake_hash()?,
            selected_credential: self.credentials.take_selected(),
        })
    }

    async fn pairing_request(
        &mut self,
        request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        self.call(request.encode(), PairingRequestApproved::decode)
            .await
    }

    async fn select_pairing_method(
        &mut self,
        request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        let mut response = self
            .call(request.encode(), SelectMethodResponse::decode)
            .await?;
        if request.method == PairingMethod::Nfc
            && let SelectMethodResponse::PairingPreparationsFinished { nfc_data } = &mut response
        {
            *nfc_data = Some(self.prepare_nfc_pairing()?);
        }
        Ok(response)
    }

    async fn code_entry_challenge(
        &mut self,
        request: CodeEntryChallengeRequest,
    ) -> BackendResult<CodeEntryChallengeResponse> {
        self.call(request.encode(), CodeEntryChallengeResponse::decode)
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
            } => self.send_qr_code_tag(handshake_hash, tag).await,
            PairingTagRequest::Nfc {
                handshake_hash,
                tag,
            } => self.send_nfc_tag(handshake_hash, tag).await,
            PairingTagRequest::CodeEntry {
                code,
                handshake_hash,
                commitment,
                challenge,
                trezor_cpace_public_key,
            } => {
                self.send_code_entry_tag(
                    code,
                    handshake_hash,
                    commitment,
                    challenge,
                    trezor_cpace_public_key,
                )
                .await
            }
        }
    }

    async fn credential_request(
        &mut self,
        request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        self.call(request.encode()?, CredentialResponse::decode)
            .await
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        self.call(
            messages::ThpEndRequest {}.to_message(),
            |message_type, payload| {
                messages::ThpEndResponse::from_message(message_type, payload).map(drop)
            },
        )
        .await?;
        self.end_pairing()
    }

    async fn create_new_session(
        &mut self,
        request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        self.call(request.encode(), |message_type, _| {
            CreateSessionResponse::decode(message_type)
        })
        .await
    }

    async fn get_address(
        &mut self,
        request: GetAddressRequest,
    ) -> BackendResult<GetAddressResponse> {
        let chain = request.chain;
        let mut response = self
            .call(request.encode(), |message_type, payload| {
                GetAddressResponse::decode(chain, message_type, payload)
            })
            .await?;
        if request.include_public_key {
            // Mirror Suite: keep GetPublicKey silent to avoid extra prompts.
            let public_key = self.get_public_key(chain, request.path).await?;
            response.public_key = Some(public_key);
        }
        Ok(response)
    }

    async fn get_public_key(&mut self, chain: Chain, path: Vec<u32>) -> BackendResult<String> {
        let request = GetPublicKeyRequest::new(chain, path);
        self.call(request.encode(), |message_type, payload| {
            request.decode_response(message_type, payload)
        })
        .await
    }

    async fn get_nonce(&mut self) -> BackendResult<Vec<u8>> {
        self.call(GetNonce {}.to_message(), |message_type, payload| {
            Ok(Nonce::from_message(message_type, payload)?.nonce)
        })
        .await
    }

    async fn sign_message(
        &mut self,
        request: SignMessageRequest,
    ) -> BackendResult<SignMessageResponse> {
        self.call(request.encode()?, |message_type, payload| {
            SignMessageResponse::decode(request.chain, message_type, payload)
        })
        .await
    }

    async fn sign_typed_data(
        &mut self,
        request: SignTypedDataRequest,
    ) -> BackendResult<SignTypedDataResponse> {
        let encoded = request.encode()?;
        let SignTypedDataPayload::TypedData(typed_data) = request.payload else {
            return self.call(encoded, SignTypedDataResponse::decode).await;
        };
        let (message_type, payload) = self.request(encoded).await?;
        self.sign_eip712(&typed_data, message_type, payload).await
    }

    async fn sign_tx(&mut self, request: SignTxRequest) -> BackendResult<SignTxResponse> {
        let (message_type, payload) = self.request(request.encode()).await?;
        match &request {
            SignTxRequest::Ethereum(tx) => self.sign_ethereum_tx(tx, message_type, payload).await,
            SignTxRequest::Bitcoin(tx) => self.sign_bitcoin_tx(tx, message_type, payload).await,
            SignTxRequest::Solana(_) => Self::solana_signature(message_type, &payload),
        }
    }

    async fn abort(&mut self) -> BackendResult<()> {
        self.reset_channel();
        Ok(self.link.disconnect().await?)
    }
}
