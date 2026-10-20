use prost::Message;

use super::wire::wire_messages;
use super::{ProtoMappingError, WireMessage};
use crate::thp::types::DeviceFeatures;

#[derive(Clone, PartialEq, Message)]
pub struct GetFeatures {}

/// Subset of firmware `Features` that hosts use to identify and gate devices.
#[derive(Clone, PartialEq, Message)]
pub struct FeaturesProto {
    #[prost(string, optional, tag = "1")]
    pub vendor: Option<String>,
    #[prost(uint32, optional, tag = "2")]
    pub major_version: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub minor_version: Option<u32>,
    #[prost(uint32, optional, tag = "4")]
    pub patch_version: Option<u32>,
    #[prost(bool, optional, tag = "5")]
    pub bootloader_mode: Option<bool>,
    #[prost(string, optional, tag = "6")]
    pub device_id: Option<String>,
    #[prost(bool, optional, tag = "7")]
    pub pin_protection: Option<bool>,
    #[prost(bool, optional, tag = "8")]
    pub passphrase_protection: Option<bool>,
    #[prost(string, optional, tag = "10")]
    pub label: Option<String>,
    #[prost(bool, optional, tag = "12")]
    pub initialized: Option<bool>,
    #[prost(bool, optional, tag = "16")]
    pub unlocked: Option<bool>,
    #[prost(string, optional, tag = "21")]
    pub model: Option<String>,
    #[prost(bool, optional, tag = "36")]
    pub passphrase_always_on_device: Option<bool>,
    #[prost(string, optional, tag = "44")]
    pub internal_model: Option<String>,
}

wire_messages! {
    FeaturesProto = 17,
    GetFeatures = 55,
}

impl DeviceFeatures {
    pub fn decode(message_type: u16, payload: &[u8]) -> Result<Self, ProtoMappingError> {
        let proto = FeaturesProto::from_message(message_type, payload)?;
        Ok(Self {
            vendor: proto.vendor,
            major_version: proto.major_version.unwrap_or_default(),
            minor_version: proto.minor_version.unwrap_or_default(),
            patch_version: proto.patch_version.unwrap_or_default(),
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

        let features = DeviceFeatures::decode(17, &payload).unwrap();
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
}
