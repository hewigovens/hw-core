use prost::Message;

use super::ProtoMappingError;

#[derive(Debug)]
pub struct EncodedMessage {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

pub trait WireMessage: Message + Default {
    const MESSAGE_TYPE: u16;

    fn to_message(&self) -> EncodedMessage {
        EncodedMessage {
            message_type: Self::MESSAGE_TYPE,
            payload: self.encode_to_vec(),
        }
    }

    fn from_message(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        if message_type != Self::MESSAGE_TYPE {
            return Err(ProtoMappingError::UnexpectedMessage(message_type));
        }
        Ok(Self::decode(payload)?)
    }
}

macro_rules! wire_messages {
    ($($message:ty = $message_type:expr),+ $(,)?) => {
        $(impl $crate::thp::proto::WireMessage for $message {
            const MESSAGE_TYPE: u16 = $message_type;
        })+
    };
}

pub(crate) use wire_messages;
