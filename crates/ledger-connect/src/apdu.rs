use crate::{LedgerError, protocol::*};

pub trait ApduTransport {
    fn exchange(
        &mut self,
        command: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, LedgerError>> + Send;
}

pub(crate) struct Apdu;

impl Apdu {
    pub fn command(cla: u8, ins: u8, p1: u8, data: &[u8]) -> Result<Vec<u8>, LedgerError> {
        Self::command_with_p2(cla, ins, p1, 0, data)
    }

    pub fn command_with_p2(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> Result<Vec<u8>, LedgerError> {
        let length = u8::try_from(data.len())
            .map_err(|_| LedgerError::InvalidInput("APDU exceeds 255 bytes"))?;
        let mut command = vec![cla, ins, p1, p2, length];
        command.extend_from_slice(data);
        Ok(command)
    }

    pub fn split_response(mut bytes: Vec<u8>) -> Result<(u16, Vec<u8>), LedgerError> {
        if bytes.len() < 2 {
            return Err(LedgerError::Protocol("missing status word"));
        }
        let end = bytes.len() - 2;
        let status = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
        bytes.truncate(end);
        Ok((status, bytes))
    }

    pub fn response(bytes: Vec<u8>) -> Result<Vec<u8>, LedgerError> {
        let (status, bytes) = Self::split_response(bytes)?;
        Self::check_status(status)?;
        Ok(bytes)
    }

    pub fn check_status(status: u16) -> Result<(), LedgerError> {
        match status {
            STATUS_OK => Ok(()),
            STATUS_SECURITY | STATUS_REJECTED | STATUS_ETH_REJECTED => Err(LedgerError::Rejected),
            STATUS_LOCKED => Err(LedgerError::Locked),
            STATUS_INS_UNSUPPORTED | STATUS_CLA_UNSUPPORTED => Err(LedgerError::Unsupported),
            other => Err(LedgerError::Status(other)),
        }
    }
}
