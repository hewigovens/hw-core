use prost::Message;

use super::wire::wire_messages;
use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::messages;
use crate::thp::types::{CreateSessionRequest, CreateSessionResponse};

pub(crate) const MESSAGE_TYPE_SUCCESS: u16 = 2;

#[derive(Clone, PartialEq, Message)]
pub struct GetNonce {}

#[derive(Clone, PartialEq, Message)]
pub struct Nonce {
    #[prost(bytes = "vec", required, tag = "1")]
    pub nonce: Vec<u8>,
}

wire_messages! {
    GetNonce = 31,
    Nonce = 33,
    messages::ThpCreateNewSession = 1000,
}

impl CreateSessionRequest {
    pub fn encode(&self) -> EncodedMessage {
        messages::ThpCreateNewSession {
            passphrase: self.passphrase.clone(),
            on_device: self.on_device.then_some(true),
            derive_cardano: self.derive_cardano.then_some(true),
        }
        .to_message()
    }
}

impl CreateSessionResponse {
    /// The device answers with a bare `Success`; its payload carries nothing we use.
    pub fn decode(message_type: u16) -> Result<Self, ProtoMappingError> {
        if message_type != MESSAGE_TYPE_SUCCESS {
            return Err(ProtoMappingError::UnexpectedMessage(message_type));
        }
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_create_session_flags_only_when_set() {
        let mut request = CreateSessionRequest {
            passphrase: None,
            on_device: false,
            derive_cardano: false,
        };
        let encoded = request.encode();
        assert_eq!(encoded.message_type, 1000);
        assert!(encoded.payload.is_empty());

        request.passphrase = Some("pw".into());
        request.on_device = true;
        request.derive_cardano = true;
        let decoded =
            messages::ThpCreateNewSession::decode(request.encode().payload.as_slice()).unwrap();
        assert_eq!(decoded.passphrase.as_deref(), Some("pw"));
        assert_eq!(decoded.on_device, Some(true));
        assert_eq!(decoded.derive_cardano, Some(true));

        assert!(CreateSessionResponse::decode(MESSAGE_TYPE_SUCCESS).is_ok());
        assert!(matches!(
            CreateSessionResponse::decode(3),
            Err(ProtoMappingError::UnexpectedMessage(3))
        ));
    }

    #[test]
    fn encodes_and_decodes_get_nonce() {
        let encoded = GetNonce {}.to_message();
        assert_eq!(encoded.message_type, 31);
        assert!(encoded.payload.is_empty());

        let payload = Nonce {
            nonce: vec![0xAA; 32],
        }
        .encode_to_vec();
        assert_eq!(
            Nonce::from_message(33, &payload).unwrap().nonce,
            vec![0xAA; 32]
        );
        assert!(matches!(
            Nonce::from_message(34, &payload),
            Err(ProtoMappingError::UnexpectedMessage(34))
        ));
    }
}
