use crate::LedgerError;

#[allow(async_fn_in_trait)]
pub trait ApduTransport {
    async fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, LedgerError>;
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

    pub fn response(mut bytes: Vec<u8>) -> Result<Vec<u8>, LedgerError> {
        if bytes.len() < 2 {
            return Err(LedgerError::Protocol("missing status word"));
        }
        let end = bytes.len() - 2;
        let status = u16::from_be_bytes([bytes[end], bytes[end + 1]]);
        bytes.truncate(end);
        match status {
            0x9000 => Ok(bytes),
            0x6982 | 0x6985 | 0x5501 => Err(LedgerError::Rejected),
            0x5515 => Err(LedgerError::Locked),
            0x6d00 | 0x6e00 => Err(LedgerError::Unsupported),
            other => Err(LedgerError::Status(other)),
        }
    }
}
