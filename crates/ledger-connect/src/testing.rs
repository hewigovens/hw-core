//! Scripted APDU transport for deterministic wallet and protocol tests.
use crate::{ApduTransport, LedgerError};
use std::collections::VecDeque;

#[derive(Default)]
pub struct ScriptedTransport<const WAIT_WHEN_EMPTY: bool = false> {
    pub responses: VecDeque<Vec<u8>>,
    pub commands: Vec<Vec<u8>>,
}

impl<const WAIT: bool> ApduTransport for ScriptedTransport<WAIT> {
    async fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError> {
        self.commands.push(command.to_vec());
        match self.responses.pop_front() {
            Some(response) => Ok(response),
            None if WAIT => std::future::pending().await,
            None => Err(LedgerError::Protocol("unexpected scripted command")),
        }
    }
}

impl<const WAIT: bool> ScriptedTransport<WAIT> {
    pub fn app_info(name: &str, version: &str) -> Vec<u8> {
        let mut response = vec![1, u8::try_from(name.len()).expect("app name fits")];
        response.extend(name.as_bytes());
        response.push(u8::try_from(version.len()).expect("version fits"));
        response.extend(version.as_bytes());
        response.extend([1, 0, 0x90, 0]);
        response
    }
}
