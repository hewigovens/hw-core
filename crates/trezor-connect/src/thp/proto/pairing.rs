use prost::Message;

use super::wire::wire_messages;
use super::{EncodedMessage, ProtoMappingError, WireMessage};
use crate::thp::messages::{self, ThpMessageType};
use crate::thp::types::{
    CodeEntryChallengeRequest, CodeEntryChallengeResponse, PairingMethod, PairingRequest,
    PairingRequestApproved, SelectMethodRequest, SelectMethodResponse,
};

wire_messages! {
    messages::ThpPairingRequest = ThpMessageType::ThpPairingRequest as u16,
    messages::ThpPairingRequestApproved = ThpMessageType::ThpPairingRequestApproved as u16,
    messages::ThpSelectMethod = ThpMessageType::ThpSelectMethod as u16,
    messages::ThpPairingPreparationsFinished = ThpMessageType::ThpPairingPreparationsFinished as u16,
    messages::ThpCredentialRequest = ThpMessageType::ThpCredentialRequest as u16,
    messages::ThpCredentialResponse = ThpMessageType::ThpCredentialResponse as u16,
    messages::ThpEndRequest = ThpMessageType::ThpEndRequest as u16,
    messages::ThpEndResponse = ThpMessageType::ThpEndResponse as u16,
    messages::ThpCodeEntryCommitment = ThpMessageType::ThpCodeEntryCommitment as u16,
    messages::ThpCodeEntryChallenge = ThpMessageType::ThpCodeEntryChallenge as u16,
    messages::ThpCodeEntryCpaceTrezor = ThpMessageType::ThpCodeEntryCpaceTrezor as u16,
    messages::ThpCodeEntryCpaceHostTag = ThpMessageType::ThpCodeEntryCpaceHostTag as u16,
    messages::ThpCodeEntrySecret = ThpMessageType::ThpCodeEntrySecret as u16,
    messages::ThpQrCodeTag = ThpMessageType::ThpQrCodeTag as u16,
    messages::ThpQrCodeSecret = ThpMessageType::ThpQrCodeSecret as u16,
    messages::ThpNfcTagHost = ThpMessageType::ThpNfcTagHost as u16,
    messages::ThpNfcTagTrezor = ThpMessageType::ThpNfcTagTrezor as u16,
}

impl From<PairingMethod> for messages::ThpPairingMethod {
    fn from(method: PairingMethod) -> Self {
        match method {
            PairingMethod::SkipPairing => Self::SkipPairing,
            PairingMethod::CodeEntry => Self::CodeEntry,
            PairingMethod::QrCode => Self::QrCode,
            PairingMethod::Nfc => Self::Nfc,
        }
    }
}

impl TryFrom<i32> for PairingMethod {
    type Error = ProtoMappingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match messages::ThpPairingMethod::try_from(value) {
            Ok(messages::ThpPairingMethod::SkipPairing) => Ok(Self::SkipPairing),
            Ok(messages::ThpPairingMethod::CodeEntry) => Ok(Self::CodeEntry),
            Ok(messages::ThpPairingMethod::QrCode) => Ok(Self::QrCode),
            Ok(messages::ThpPairingMethod::Nfc) => Ok(Self::Nfc),
            Err(_) => Err(ProtoMappingError::InvalidEnum(value)),
        }
    }
}

impl PairingRequest {
    pub fn encode(&self) -> EncodedMessage {
        messages::ThpPairingRequest {
            host_name: self.host_name.clone(),
            app_name: self.app_name.clone(),
        }
        .to_message()
    }
}

impl PairingRequestApproved {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        messages::ThpPairingRequestApproved::from_message(message_type, payload)?;
        Ok(Self)
    }
}

impl SelectMethodRequest {
    pub fn encode(&self) -> EncodedMessage {
        messages::ThpSelectMethod {
            selected_pairing_method: messages::ThpPairingMethod::from(self.method) as i32,
        }
        .to_message()
    }
}

impl SelectMethodResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        match message_type {
            messages::ThpEndResponse::MESSAGE_TYPE => {
                messages::ThpEndResponse::decode(payload)?;
                Ok(Self::End)
            }
            messages::ThpCodeEntryCommitment::MESSAGE_TYPE => {
                let message = messages::ThpCodeEntryCommitment::decode(payload)?;
                Ok(Self::CodeEntryCommitment {
                    commitment: message.commitment,
                })
            }
            messages::ThpPairingPreparationsFinished::MESSAGE_TYPE => {
                messages::ThpPairingPreparationsFinished::decode(payload)?;
                Ok(Self::PairingPreparationsFinished { nfc_data: None })
            }
            _ => Err(ProtoMappingError::UnexpectedMessage(message_type)),
        }
    }
}

impl CodeEntryChallengeRequest {
    pub fn encode(&self) -> EncodedMessage {
        messages::ThpCodeEntryChallenge {
            challenge: self.challenge.clone(),
        }
        .to_message()
    }
}

impl CodeEntryChallengeResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let message = messages::ThpCodeEntryCpaceTrezor::from_message(message_type, payload)?;
        Ok(Self {
            trezor_cpace_public_key: message.cpace_trezor_public_key,
        })
    }
}

/// The device secret revealed in reply to a QR, NFC or code-entry pairing tag.
pub struct ParsedTagResponse {
    pub secret: Vec<u8>,
}

impl ParsedTagResponse {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let secret = match message_type {
            messages::ThpQrCodeSecret::MESSAGE_TYPE => {
                messages::ThpQrCodeSecret::decode(payload)?.secret
            }
            messages::ThpNfcTagTrezor::MESSAGE_TYPE => {
                messages::ThpNfcTagTrezor::decode(payload)?.tag
            }
            messages::ThpCodeEntrySecret::MESSAGE_TYPE => {
                messages::ThpCodeEntrySecret::decode(payload)?.secret
            }
            _ => return Err(ProtoMappingError::UnexpectedMessage(message_type)),
        };
        Ok(Self { secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_methods_round_trip_through_wire_values() {
        for method in [
            PairingMethod::SkipPairing,
            PairingMethod::CodeEntry,
            PairingMethod::QrCode,
            PairingMethod::Nfc,
        ] {
            let encoded = SelectMethodRequest { method }.encode();
            assert_eq!(encoded.message_type, 1010);
            let message = messages::ThpSelectMethod::decode(encoded.payload.as_slice()).unwrap();
            assert_eq!(
                PairingMethod::try_from(message.selected_pairing_method).unwrap(),
                method
            );
        }
        assert!(matches!(
            PairingMethod::try_from(9),
            Err(ProtoMappingError::InvalidEnum(9))
        ));
    }

    #[test]
    fn encodes_code_entry_challenge_and_decodes_cpace_response() {
        let encoded = CodeEntryChallengeRequest {
            challenge: vec![0x42; 32],
        }
        .encode();
        assert_eq!(
            encoded.message_type,
            ThpMessageType::ThpCodeEntryChallenge as u16
        );
        let decoded = messages::ThpCodeEntryChallenge::decode(encoded.payload.as_slice()).unwrap();
        assert_eq!(decoded.challenge, vec![0x42; 32]);

        let payload = messages::ThpCodeEntryCpaceTrezor {
            cpace_trezor_public_key: vec![0x77; 32],
        }
        .encode_to_vec();
        let decoded = CodeEntryChallengeResponse::decode(
            ThpMessageType::ThpCodeEntryCpaceTrezor as u16,
            &payload,
        )
        .unwrap();
        assert_eq!(decoded.trezor_cpace_public_key, vec![0x77; 32]);
    }

    #[test]
    fn decodes_select_method_responses() {
        let commitment = messages::ThpCodeEntryCommitment {
            commitment: vec![4; 32],
        }
        .encode_to_vec();
        assert!(matches!(
            SelectMethodResponse::decode(ThpMessageType::ThpEndResponse as u16, &[]),
            Ok(SelectMethodResponse::End)
        ));
        assert!(matches!(
            SelectMethodResponse::decode(ThpMessageType::ThpCodeEntryCommitment as u16, &commitment),
            Ok(SelectMethodResponse::CodeEntryCommitment { commitment }) if commitment == vec![4; 32]
        ));
        assert!(matches!(
            SelectMethodResponse::decode(
                ThpMessageType::ThpPairingPreparationsFinished as u16,
                &[]
            ),
            Ok(SelectMethodResponse::PairingPreparationsFinished { nfc_data: None })
        ));
        for message_type in [ThpMessageType::ThpQrCodeSecret as u16, 9999] {
            assert!(matches!(
                SelectMethodResponse::decode(message_type, &[]),
                Err(ProtoMappingError::UnexpectedMessage(t)) if t == message_type
            ));
        }
    }

    #[test]
    fn decodes_tag_secret_from_each_pairing_method() {
        let cases = [
            (
                ThpMessageType::ThpQrCodeSecret,
                messages::ThpQrCodeSecret {
                    secret: vec![1; 32],
                }
                .encode_to_vec(),
                vec![1; 32],
            ),
            (
                ThpMessageType::ThpNfcTagTrezor,
                messages::ThpNfcTagTrezor { tag: vec![2; 32] }.encode_to_vec(),
                vec![2; 32],
            ),
            (
                ThpMessageType::ThpCodeEntrySecret,
                messages::ThpCodeEntrySecret {
                    secret: vec![3; 32],
                }
                .encode_to_vec(),
                vec![3; 32],
            ),
        ];
        for (message_type, payload, secret) in cases {
            assert_eq!(
                ParsedTagResponse::decode(message_type as u16, &payload)
                    .unwrap()
                    .secret,
                secret
            );
        }
        assert!(matches!(
            ParsedTagResponse::decode(ThpMessageType::ThpEndResponse as u16, &[]),
            Err(ProtoMappingError::UnexpectedMessage(1019))
        ));
    }
}
