use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use prost::Message;
use trezor_thp::channel::PRIVKEY_LEN;
use trezor_thp::credential::{CredentialStore, FoundCredential};

use crate::thp::messages;
use crate::thp::types::KnownCredential;

#[derive(Default)]
struct HostCredentials {
    static_key: [u8; PRIVKEY_LEN],
    known: Vec<KnownCredential>,
    selected: Option<KnownCredential>,
}

/// Always supplies the persistent host key so issued credentials stay bound to it.
#[derive(Clone, Default)]
pub(super) struct SharedCredentials(Arc<Mutex<HostCredentials>>);

impl SharedCredentials {
    fn lock(&self) -> MutexGuard<'_, HostCredentials> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Arms the store for the next handshake, clearing any previously selected credential.
    pub(super) fn prepare(&self, static_key: [u8; PRIVKEY_LEN], known: Vec<KnownCredential>) {
        *self.lock() = HostCredentials {
            static_key,
            known,
            selected: None,
        };
    }

    pub(super) fn take_selected(&self) -> Option<KnownCredential> {
        self.lock().selected.take()
    }
}

impl CredentialStore for SharedCredentials {
    fn lookup<'a>(
        &self,
        ephemeral_pubkey: &[u8],
        masked_static_pubkey: &[u8],
        dest: &'a mut [u8],
    ) -> Option<FoundCredential<'a>> {
        let mut credentials = self.lock();
        let ephemeral: &[u8; 32] = ephemeral_pubkey.try_into().ok()?;
        let masked: &[u8; 32] = masked_static_pubkey.try_into().ok()?;
        let selected = credentials
            .known
            .iter()
            .find(|credential| credential.matches_masked_key(masked, ephemeral))
            .cloned();
        let payload = messages::ThpHandshakeCompletionReqNoisePayload {
            host_pairing_credential: selected
                .as_ref()
                .and_then(|c| hex::decode(&c.credential).ok()),
        }
        .encode_to_vec();
        credentials.selected = selected;

        if dest.len() < PRIVKEY_LEN + payload.len() {
            return None;
        }
        let (key, rest) = dest.split_at_mut(PRIVKEY_LEN);
        key.copy_from_slice(&credentials.static_key);
        rest[..payload.len()].copy_from_slice(&payload);
        let key: &'a [u8] = key;
        let rest: &'a [u8] = rest;
        Some(FoundCredential {
            local_static_privkey: key.try_into().ok()?,
            auth_credential: &rest[..payload.len()],
        })
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::thp::crypto::Curve25519KeyPair;
    use crate::thp::crypto::curve25519::curve25519;

    #[test]
    fn credential_lookup_always_uses_host_key_and_sends_matching_credential() {
        let mut rng = rand::rng();
        let trezor_static = Curve25519KeyPair::generate(&mut rng);
        let ephemeral = Curve25519KeyPair::generate(&mut rng).public_key;
        let mask: [u8; 32] = Sha256::new()
            .chain_update(trezor_static.public_key)
            .chain_update(ephemeral)
            .finalize()
            .into();
        let masked = curve25519(&mask, &trezor_static.public_key);

        let credentials = SharedCredentials::default();
        credentials.prepare(
            [0x42; 32],
            vec![
                KnownCredential {
                    credential: "0011".into(),
                    trezor_static_public_key: Some(vec![0x99; 32]),
                    autoconnect: false,
                },
                KnownCredential {
                    credential: "aabb".into(),
                    trezor_static_public_key: Some(trezor_static.public_key.to_vec()),
                    autoconnect: true,
                },
            ],
        );

        let mut dest = [0u8; 160];
        let found = credentials
            .lookup(&ephemeral, &masked, &mut dest)
            .expect("host key is always supplied");
        assert_eq!(found.local_static_privkey, &[0x42; 32]);
        let payload =
            messages::ThpHandshakeCompletionReqNoisePayload::decode(found.auth_credential)
                .expect("noise payload");
        assert_eq!(payload.host_pairing_credential, Some(vec![0xaa, 0xbb]));
        assert_eq!(
            credentials.take_selected().map(|c| c.credential),
            Some("aabb".into())
        );

        let found = credentials
            .lookup(&ephemeral, &[0x01; 32], &mut dest)
            .expect("host key is always supplied");
        assert_eq!(found.local_static_privkey, &[0x42; 32]);
        assert!(found.auth_credential.is_empty());
        assert!(credentials.take_selected().is_none());
    }
}
