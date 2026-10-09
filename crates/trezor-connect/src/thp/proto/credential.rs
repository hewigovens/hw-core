use hex::FromHex;

use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::messages;
use crate::thp::types::{CredentialRequest, CredentialResponse};

impl CredentialRequest {
    pub fn encode(&self) -> Result<EncodedMessage, ProtoMappingError> {
        Ok(messages::ThpCredentialRequest {
            host_static_public_key: self.host_static_public_key.clone(),
            autoconnect: Some(self.autoconnect),
            credential: self.credential.as_ref().map(Vec::from_hex).transpose()?,
        }
        .to_message())
    }
}

impl CredentialResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let message = messages::ThpCredentialResponse::from_message(message_type, payload)?;
        Ok(Self {
            trezor_static_public_key: message.trezor_static_public_key,
            credential: hex::encode(message.credential),
            autoconnect: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    #[test]
    fn encodes_credential_request_with_hex_credential() {
        let mut request = CredentialRequest {
            autoconnect: true,
            host_static_public_key: vec![7; 32],
            credential: Some("0a0b".into()),
        };
        let encoded = request.encode().unwrap();
        assert_eq!(
            encoded.message_type,
            messages::ThpCredentialRequest::MESSAGE_TYPE
        );
        let decoded = messages::ThpCredentialRequest::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.host_static_public_key, vec![7; 32]);
        assert_eq!(decoded.autoconnect, Some(true));
        assert_eq!(decoded.credential, Some(vec![0x0a, 0x0b]));

        request.credential = Some("zz".into());
        assert!(matches!(
            request.encode(),
            Err(ProtoMappingError::InvalidHex(_))
        ));
    }

    #[test]
    fn decodes_credential_response_as_hex() {
        let payload = messages::ThpCredentialResponse {
            trezor_static_public_key: vec![1; 32],
            credential: vec![0xab, 0xcd],
        }
        .encode_to_vec();
        let response =
            CredentialResponse::decode(messages::ThpCredentialResponse::MESSAGE_TYPE, &payload)
                .unwrap();
        assert_eq!(response.trezor_static_public_key, vec![1; 32]);
        assert_eq!(response.credential, "abcd");
        assert!(!response.autoconnect);
    }
}
