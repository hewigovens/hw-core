use prost::Message;

use super::wire::wire_messages;
use super::{ProtoMappingError, WireMessage};
use crate::thp::types::DeviceFeatures;

#[derive(Clone, PartialEq, Message)]
pub(crate) struct GetFeatures {}

/// Subset of firmware `Features` that hosts use to identify and gate devices.
#[derive(Clone, PartialEq, Message)]
pub(crate) struct FeaturesProto {
    #[prost(string, optional, tag = "1")]
    pub(crate) vendor: Option<String>,
    #[prost(uint32, optional, tag = "2")]
    pub(crate) major_version: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub(crate) minor_version: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub(crate) patch_version: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub(crate) bootloader_mode: Option<bool>,
    #[prost(string, optional, tag = "6")]
    pub(crate) device_id: Option<String>,
    #[prost(bool, optional, tag = "7")]
    pub(crate) pin_protection: Option<bool>,
    #[prost(bool, optional, tag = "8")]
    pub(crate) passphrase_protection: Option<bool>,
    #[prost(string, optional, tag = "10")]
    pub(crate) label: Option<String>,
    #[prost(bool, optional, tag = "12")]
    pub(crate) initialized: Option<bool>,
    #[prost(bool, optional, tag = "16")]
    pub(crate) unlocked: Option<bool>,
    #[prost(string, optional, tag = "21")]
    pub(crate) model: Option<String>,
    #[prost(bool, optional, tag = "36")]
    pub(crate) passphrase_always_on_device: Option<bool>,
    #[prost(string, optional, tag = "44")]
    pub(crate) internal_model: Option<String>,
}

wire_messages! {
    FeaturesProto = 17,
    GetFeatures = 55,
}

impl DeviceFeatures {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let proto = FeaturesProto::from_message(message_type, payload)?;
        // Required in the firmware proto; defaulting them would report firmware 0.0.0.
        let required =
            |value: Option<u32>, field| value.ok_or(ProtoMappingError::MissingField(field));
        Ok(Self {
            vendor: proto.vendor,
            major_version: required(proto.major_version, "major_version")?,
            minor_version: required(proto.minor_version, "minor_version")?,
            patch_version: required(proto.patch_version, "patch_version")?,
            device_id: proto.device_id,
            label: proto.label,
            model: proto.model,
            internal_model: proto.internal_model,
            bootloader_mode: proto.bootloader_mode.unwrap_or_default(),
            initialized: proto.initialized.unwrap_or_default(),
            unlocked: proto.unlocked.unwrap_or_default(),
            pin_protection: proto.pin_protection.unwrap_or_default(),
            passphrase_protection: proto.passphrase_protection.unwrap_or_default(),
            passphrase_always_on_device: proto.passphrase_always_on_device.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_features_identity_version_and_passphrase_state() {
        let payload = FeaturesProto {
            vendor: Some("trezor.io".into()),
            major_version: Some(2),
            minor_version: Some(9),
            patch_version: Some(4),
            device_id: Some("ABCDEF0123".into()),
            label: Some("My Trezor".into()),
            model: Some("Safe 7".into()),
            internal_model: Some("T3W1".into()),
            passphrase_protection: Some(true),
            unlocked: Some(true),
            ..FeaturesProto::default()
        }
        .encode_to_vec();

        let features = DeviceFeatures::decode(FeaturesProto::MESSAGE_TYPE, &payload).unwrap();
        assert_eq!(features.device_id.as_deref(), Some("ABCDEF0123"));
        assert_eq!(features.internal_model.as_deref(), Some("T3W1"));
        assert!(features.passphrase_protection);
        assert!(!features.bootloader_mode);
        assert!(features.version_at_least(2, 9, 4));
        assert!(!features.version_at_least(2, 10, 0));
        assert!(matches!(
            DeviceFeatures::decode(3, &payload),
            Err(ProtoMappingError::UnexpectedMessage(3))
        ));
    }

    #[test]
    fn rejects_features_without_required_version_fields() {
        let complete = FeaturesProto {
            major_version: Some(2),
            minor_version: Some(13),
            patch_version: Some(0),
            ..FeaturesProto::default()
        };
        type ClearField = fn(&mut FeaturesProto);
        let cases: [(&str, ClearField); 3] = [
            ("major_version", |proto| proto.major_version = None),
            ("minor_version", |proto| proto.minor_version = None),
            ("patch_version", |proto| proto.patch_version = None),
        ];
        for (field, clear) in cases {
            let mut proto = complete.clone();
            clear(&mut proto);
            assert!(matches!(
                DeviceFeatures::decode(FeaturesProto::MESSAGE_TYPE, &proto.encode_to_vec()),
                Err(ProtoMappingError::MissingField(missing)) if missing == field
            ));
        }
    }
}
