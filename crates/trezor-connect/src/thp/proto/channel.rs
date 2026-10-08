use prost::Message;

use super::ProtoMappingError;
use crate::thp::messages;
use crate::thp::types::{PairingMethod, ThpProperties};

impl ThpProperties {
    /// Decodes the `ThpDeviceProperties` carried by the channel allocation response.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let message = messages::ThpDeviceProperties::decode(payload)?;
        Ok(Self {
            internal_model: message.internal_model,
            model_variant: message.model_variant.unwrap_or(0),
            protocol_version_major: message.protocol_version_major,
            protocol_version_minor: message.protocol_version_minor,
            pairing_methods: message
                .pairing_methods
                .into_iter()
                .map(PairingMethod::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn properties(model_variant: Option<u32>, pairing_methods: Vec<i32>) -> Vec<u8> {
        messages::ThpDeviceProperties {
            internal_model: "T3W1".into(),
            model_variant,
            protocol_version_major: 2,
            protocol_version_minor: 1,
            pairing_methods,
        }
        .encode_to_vec()
    }

    #[test]
    fn decodes_device_properties() {
        let decoded = ThpProperties::decode(&properties(None, vec![1, 2, 3, 4])).unwrap();
        assert_eq!(decoded.internal_model, "T3W1");
        assert_eq!(decoded.model_variant, 0);
        assert_eq!(
            (
                decoded.protocol_version_major,
                decoded.protocol_version_minor
            ),
            (2, 1)
        );
        assert_eq!(
            decoded.pairing_methods,
            vec![
                PairingMethod::SkipPairing,
                PairingMethod::CodeEntry,
                PairingMethod::QrCode,
                PairingMethod::Nfc
            ]
        );

        assert!(matches!(
            ThpProperties::decode(&properties(Some(3), vec![1, 9])),
            Err(ProtoMappingError::InvalidEnum(9))
        ));
    }
}
