use super::LedgerClient;
use crate::{ApduTransport, LedgerError, apdu::Apdu};

impl<T: ApduTransport> LedgerClient<T> {
    pub async fn solana_public_key(
        &mut self,
        path: &[u32],
        display: bool,
    ) -> Result<[u8; 32], LedgerError> {
        let path = Self::solana_path(path)?;
        self.ensure_app("Solana").await?;
        self.ready = false;
        let command = Apdu::command(0xe0, 0x05, u8::from(display), &path)?;
        let response = Apdu::response(self.transport.exchange(&command).await?)?;
        let key = response
            .try_into()
            .map_err(|_| LedgerError::Protocol("invalid Solana public key length"))?;
        self.ready = true;
        Ok(key)
    }

    pub async fn sign_solana_transaction(
        &mut self,
        path: &[u32],
        message: &[u8],
    ) -> Result<[u8; 64], LedgerError> {
        self.sign_solana(0x06, path, message).await
    }

    pub async fn sign_solana_offchain_message(
        &mut self,
        path: &[u32],
        envelope: &[u8],
    ) -> Result<[u8; 64], LedgerError> {
        self.sign_solana(0x07, path, envelope).await
    }

    async fn sign_solana(
        &mut self,
        instruction: u8,
        path: &[u32],
        message: &[u8],
    ) -> Result<[u8; 64], LedgerError> {
        if message.is_empty() || message.len() > 65535 {
            return Err(LedgerError::InvalidInput(
                "Solana payload must contain 1..=65535 bytes",
            ));
        }
        let mut payload = vec![1];
        payload.extend(Self::solana_path(path)?);
        payload.extend_from_slice(message);
        self.ensure_app("Solana").await?;
        self.ready = false;
        let count = payload.len().div_ceil(255);
        for (index, chunk) in payload.chunks(255).enumerate() {
            let last = index + 1 == count;
            let p2 = u8::from(index > 0) | if last { 0 } else { 2 };
            let command = Apdu::command_with_p2(0xe0, instruction, 1, p2, chunk)?;
            let response = Apdu::response(self.transport.exchange(&command).await?)?;
            if last {
                let signature = response
                    .try_into()
                    .map_err(|_| LedgerError::Protocol("invalid Solana signature length"))?;
                self.ready = true;
                return Ok(signature);
            }
            if !response.is_empty() {
                return Err(LedgerError::Protocol(
                    "unexpected intermediate Solana response",
                ));
            }
        }
        Err(LedgerError::InvalidInput("empty Solana payload"))
    }

    fn solana_path(path: &[u32]) -> Result<Vec<u8>, LedgerError> {
        if !(2..=4).contains(&path.len())
            || path[..2] != [0x8000002c, 0x800001f5]
            || path.iter().any(|index| index & 0x80000000 == 0)
        {
            return Err(LedgerError::InvalidInput(
                "Solana path must be m/44'/501' with up to two hardened account components",
            ));
        }
        Self::encode_path(path)
    }
}
