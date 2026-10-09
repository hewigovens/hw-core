use crate::thp::types::{CredentialRequest, KnownCredential, PairingMethod, PairingTagRequest};

#[derive(Debug, Clone, Default)]
pub struct HandshakeCache {
    pub channel: u16,
    pub pairing_methods: Vec<PairingMethod>,
}

#[derive(Debug, Clone, Default)]
pub struct HandshakeCredentials {
    pub pairing_methods: Vec<PairingMethod>,
    pub handshake_hash: Vec<u8>,
    pub host_static_public_key: Vec<u8>,
    pub nfc_data: Option<Vec<u8>>,
    pub handshake_commitment: Option<Vec<u8>>,
    pub trezor_cpace_public_key: Option<Vec<u8>>,
    pub code_entry_challenge: Option<Vec<u8>>,
    pub pairing_credentials: Vec<KnownCredential>,
}

impl HandshakeCredentials {
    pub fn preferred_pairing_method(&self) -> Option<PairingMethod> {
        self.pairing_methods.first().copied()
    }

    /// Requests a credential, refreshing the one the handshake selected if any.
    pub fn credential_request(&self) -> CredentialRequest {
        CredentialRequest {
            autoconnect: false,
            host_static_public_key: self.host_static_public_key.clone(),
            credential: self
                .pairing_credentials
                .first()
                .map(|c| c.credential.clone()),
        }
    }

    pub fn has_code_entry_inputs(&self) -> bool {
        self.handshake_commitment.is_some()
            && self.code_entry_challenge.is_some()
            && self.trezor_cpace_public_key.is_some()
    }

    pub fn code_entry_tag(&self, code: String) -> PairingTagRequest {
        PairingTagRequest::CodeEntry {
            code,
            handshake_hash: self.handshake_hash.clone(),
            commitment: self.handshake_commitment.clone(),
            challenge: self.code_entry_challenge.clone(),
            trezor_cpace_public_key: self.trezor_cpace_public_key.clone(),
        }
    }
}
