#![cfg(feature = "ble")]

use std::time::Duration;

use async_trait::async_trait;
use ble_transport::{BleBackend as TransportBackend, BleLink, BleSession, DeviceInfo};
use thiserror::Error;

use crate::thp::backend::{BackendError, BackendResult, ThpBackend};
use crate::thp::types::*;
use crate::thp::ThpTransport;

#[derive(Debug, Error)]
pub enum BleWorkflowError {
    #[error("BLE backend not ready for THP")]
    NotImplemented,
}

pub struct BleBackend {
    inner: TransportBackend,
    device: DeviceInfo,
    transport: ThpTransport,
    handshake_timeout: Duration,
}

impl BleBackend {
    pub fn new(link: BleLink, device: DeviceInfo) -> Self {
        Self {
            inner: TransportBackend::new(link),
            device,
            transport: ThpTransport::new(),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    pub fn from_session(session: BleSession) -> Self {
        let (device, link) = session.into_parts();
        Self::new(link, device)
    }

    pub fn link_mut(&mut self) -> &mut BleLink {
        self.inner.link_mut()
    }
}

#[async_trait]
impl ThpBackend for BleBackend {
    async fn create_channel(
        &mut self,
        _request: CreateChannelRequest,
    ) -> BackendResult<CreateChannelResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn handshake_init(
        &mut self,
        _request: HandshakeInitRequest,
    ) -> BackendResult<HandshakeInitOutcome> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn handshake_complete(
        &mut self,
        _request: HandshakeCompletionRequest,
    ) -> BackendResult<HandshakeCompletionResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn pairing_request(
        &mut self,
        _request: PairingRequest,
    ) -> BackendResult<PairingRequestApproved> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn select_pairing_method(
        &mut self,
        _request: SelectMethodRequest,
    ) -> BackendResult<SelectMethodResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn send_pairing_tag(
        &mut self,
        _request: PairingTagRequest,
    ) -> BackendResult<PairingTagResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn credential_request(
        &mut self,
        _request: CredentialRequest,
    ) -> BackendResult<CredentialResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn end_request(&mut self) -> BackendResult<()> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn create_new_session(
        &mut self,
        _request: CreateSessionRequest,
    ) -> BackendResult<CreateSessionResponse> {
        Err(BackendError::Transport(
            BleWorkflowError::NotImplemented.to_string(),
        ))
    }

    async fn abort(&mut self) -> BackendResult<()> {
        self.transport.reset();
        self.inner
            .abort()
            .await
            .map_err(|e| BackendError::Transport(e.to_string()))
    }
}
