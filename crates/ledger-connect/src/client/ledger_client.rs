use crate::apdu::Apdu;
use crate::protocol::*;
use crate::{ApduTransport, LedgerAppInfo, LedgerError};

use super::{EthereumAddress, EthereumSignature};

pub struct LedgerClient<T> {
    pub(super) transport: T,
    pub(super) ready: bool,
}

impl<T: ApduTransport> LedgerClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            ready: true,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub async fn app_info(&mut self) -> Result<LedgerAppInfo, LedgerError> {
        LedgerAppInfo::decode(&self.command(CLA_APP_INFO, INS_APP_INFO, 0, &[]).await?)
    }

    pub(super) async fn ensure_ethereum_app(&mut self) -> Result<(), LedgerError> {
        self.ensure_app("Ethereum").await
    }

    pub(super) async fn ensure_app(&mut self, expected: &'static str) -> Result<(), LedgerError> {
        let app = self.app_info().await?;
        if app.name != expected {
            return Err(LedgerError::WrongApp {
                expected,
                actual: app.name,
            });
        }
        Ok(())
    }

    pub async fn ethereum_address(
        &mut self,
        path: &[u32],
        display: bool,
        chain_id: u64,
    ) -> Result<EthereumAddress, LedgerError> {
        let mut data = Self::encode_path(path)?;
        if display {
            data.extend_from_slice(&chain_id.to_be_bytes());
        }
        self.ensure_ethereum_app().await?;
        let response = self
            .command(CLA_APP, INS_ETH_ADDRESS, u8::from(display), &data)
            .await?;
        if response.len() != 107 || response[0] != 65 || response[1] != 4 || response[66] != 40 {
            return Err(LedgerError::Protocol("invalid Ethereum address response"));
        }
        let address = &response[67..];
        if !address.iter().all(u8::is_ascii_hexdigit) {
            return Err(LedgerError::Protocol("invalid Ethereum address hex"));
        }
        let address = std::str::from_utf8(address)
            .map_err(|_| LedgerError::Protocol("invalid address encoding"))?;
        Ok(EthereumAddress {
            address: format!("0x{address}"),
            public_key: response[1..66].to_vec(),
        })
    }

    pub async fn sign_personal_message(
        &mut self,
        path: &[u32],
        message: &[u8],
    ) -> Result<EthereumSignature, LedgerError> {
        let mut data = Self::encode_path(path)?;
        let length = u32::try_from(message.len())
            .map_err(|_| LedgerError::InvalidInput("message too large"))?;
        data.extend_from_slice(&length.to_be_bytes());
        data.extend_from_slice(message);
        self.sign_chunks(INS_ETH_PERSONAL_MESSAGE, &data).await
    }

    /// Accepts an unsigned EIP-1559 (type 2) envelope; never broadcasts it.
    /// Legacy transactions are unsupported: their v/r/s trailer needs different chunk boundaries.
    pub async fn sign_transaction(
        &mut self,
        path: &[u32],
        transaction: &[u8],
    ) -> Result<EthereumSignature, LedgerError> {
        if transaction.first() != Some(&2) {
            return Err(LedgerError::InvalidInput(
                "only EIP-1559 transaction envelopes are supported",
            ));
        }
        let mut data = Self::encode_path(path)?;
        data.extend_from_slice(transaction);
        self.sign_chunks(INS_ETH_TRANSACTION, &data).await
    }

    async fn sign_chunks(
        &mut self,
        instruction: u8,
        data: &[u8],
    ) -> Result<EthereumSignature, LedgerError> {
        if !self.ready {
            return Err(LedgerError::Disconnected);
        }
        self.ensure_ethereum_app().await?;
        // Cancellation between chunks must not allow another command into an unfinished signing flow.
        self.ready = false;
        let count = data.len().div_ceil(ETH_CHUNK_SIZE);
        for (index, chunk) in data.chunks(ETH_CHUNK_SIZE).enumerate() {
            let command = Apdu::command(
                CLA_APP,
                instruction,
                if index == 0 { 0 } else { 0x80 },
                chunk,
            )?;
            let response = self.exchange_apdu(&command).await?;
            if index + 1 == count {
                let signature = EthereumSignature::decode(&response)?;
                self.ready = true;
                return Ok(signature);
            }
            if !response.is_empty() {
                return Err(LedgerError::Protocol("unexpected intermediate signature"));
            }
        }
        Err(LedgerError::InvalidInput("empty signing payload"))
    }

    async fn command(
        &mut self,
        cla: u8,
        instruction: u8,
        p1: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerError> {
        if !self.ready {
            return Err(LedgerError::Disconnected);
        }
        let command = Apdu::command(cla, instruction, p1, data)?;
        self.ready = false;
        let response = self.exchange_apdu(&command).await?;
        self.ready = true;
        Ok(response)
    }

    pub(super) async fn exchange_apdu(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError> {
        let response = Apdu::response(self.transport.exchange(command).await?);
        if response
            .as_ref()
            .is_err_and(|error| error.is_device_response())
        {
            self.ready = true;
        }
        response
    }

    pub(super) fn encode_path(path: &[u32]) -> Result<Vec<u8>, LedgerError> {
        if path.is_empty() || path.len() > 10 {
            return Err(LedgerError::InvalidBip32Path(
                "path must contain 1 to 10 components",
            ));
        }
        let mut data = vec![path.len() as u8];
        for component in path {
            data.extend_from_slice(&component.to_be_bytes());
        }
        Ok(data)
    }
}
