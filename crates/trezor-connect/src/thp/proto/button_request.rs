use prost::Message;

use super::ProtoMappingError;
use super::wire::wire_messages;
use crate::thp::types::{ButtonRequest, ButtonRequestCode};

#[derive(Clone, PartialEq, Message)]
pub struct ButtonRequestProto {
    #[prost(int32, optional, tag = "1")]
    pub code: Option<i32>,
    #[prost(uint32, optional, tag = "2")]
    pub pages: Option<u32>,
    #[prost(string, optional, tag = "4")]
    pub name: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct ButtonAck {}

#[derive(Clone, PartialEq, Message)]
pub struct Cancel {}

wire_messages! {
    Cancel = 20,
    ButtonRequestProto = 26,
    ButtonAck = 27,
}

impl ButtonRequest {
    pub fn decode(payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let proto = ButtonRequestProto::decode(payload)?;
        Ok(Self {
            code: proto.code.and_then(ButtonRequestCode::from_wire),
            pages: proto.pages,
            name: proto.name,
        })
    }
}

impl ButtonRequestCode {
    fn from_wire(code: i32) -> Option<Self> {
        Some(match code {
            1 => Self::Other,
            2 => Self::FeeOverThreshold,
            3 => Self::ConfirmOutput,
            4 => Self::ResetDevice,
            5 => Self::ConfirmWord,
            6 => Self::WipeDevice,
            7 => Self::ProtectCall,
            8 => Self::SignTx,
            9 => Self::FirmwareCheck,
            10 => Self::Address,
            11 => Self::PublicKey,
            12 => Self::MnemonicWordCount,
            13 => Self::MnemonicInput,
            15 => Self::UnknownDerivationPath,
            16 => Self::RecoveryHomepage,
            17 => Self::Success,
            18 => Self::Warning,
            19 => Self::PassphraseEntry,
            20 => Self::PinEntry,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_button_request_screen_and_tolerates_unknown_codes() {
        let payload = ButtonRequestProto {
            code: Some(3),
            pages: Some(2),
            name: Some("confirm_output".into()),
        }
        .encode_to_vec();
        assert_eq!(
            ButtonRequest::decode(&payload).unwrap(),
            ButtonRequest {
                code: Some(ButtonRequestCode::ConfirmOutput),
                pages: Some(2),
                name: Some("confirm_output".into()),
            }
        );

        let unknown = ButtonRequestProto {
            code: Some(14),
            ..ButtonRequestProto::default()
        }
        .encode_to_vec();
        assert_eq!(ButtonRequest::decode(&unknown).unwrap().code, None);
    }
}
