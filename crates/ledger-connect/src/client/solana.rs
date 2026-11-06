use super::LedgerClient;
use crate::protocol::*;
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
        let command = Apdu::command(CLA_APP, INS_SOL_ADDRESS, u8::from(display), &path)?;
        let response = self.exchange_solana(&command).await?;
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
        self.sign_solana(INS_SOL_TRANSACTION, path, message).await
    }

    pub async fn sign_solana_offchain_message(
        &mut self,
        path: &[u32],
        envelope: &[u8],
    ) -> Result<[u8; 64], LedgerError> {
        self.sign_solana(INS_SOL_OFFCHAIN, path, envelope).await
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
        let count = payload.len().div_ceil(APDU_DATA_SIZE);
        for (index, chunk) in payload.chunks(APDU_DATA_SIZE).enumerate() {
            let last = index + 1 == count;
            let p2 = if index > 0 { SOL_EXTEND } else { 0 } | if last { 0 } else { SOL_MORE };
            let command = Apdu::command_with_p2(CLA_APP, instruction, 1, p2, chunk)?;
            let response = self.exchange_solana(&command).await?;
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

    async fn exchange_solana(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError> {
        self.exchange_apdu(command)
            .await
            .map_err(|error| match error {
                LedgerError::Status(STATUS_SOL_MESSAGE_HEADER)
                    if command[1] == INS_SOL_OFFCHAIN =>
                {
                    LedgerError::SolanaMessageHeaderUnsupported
                }
                LedgerError::Status(STATUS_SOL_BLIND_SIGNING) => {
                    LedgerError::SolanaBlindSigningRequired
                }
                error => error,
            })
    }

    fn solana_path(path: &[u32]) -> Result<Vec<u8>, LedgerError> {
        if !(2..=4).contains(&path.len())
            || path[..2] != [0x8000002c, 0x800001f5]
            || path.iter().any(|index| index & 0x80000000 == 0)
        {
            return Err(LedgerError::InvalidBip32Path(
                "Solana path must be m/44'/501' with up to two hardened account components",
            ));
        }
        Self::encode_path(path)
    }
}
