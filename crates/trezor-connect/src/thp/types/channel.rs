use serde::{Deserialize, Serialize};

use super::PairingMethod;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThpProperties {
    pub internal_model: String,
    pub model_variant: u32,
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
    pub pairing_methods: Vec<PairingMethod>,
}

#[derive(Debug, Clone)]
pub struct CreateChannelRequest {
    pub try_to_unlock: bool,
}

#[derive(Debug, Clone)]
pub struct CreateChannelResponse {
    pub channel: u16,
    pub properties: ThpProperties,
}
