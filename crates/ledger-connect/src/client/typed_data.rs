use super::{EthereumSignature, LedgerClient};
use crate::{ApduTransport, LedgerError, apdu::Apdu};

#[derive(Debug, Clone)]
pub enum Eip712Command {
    StructName(String),
    StructField(Vec<u8>),
    Root(String),
    Array(u8),
    Value(Vec<u8>),
}

impl Eip712Command {
    fn encode(&self) -> Result<Vec<Vec<u8>>, LedgerError> {
        let (ins, p2, data) = match self {
            Self::StructName(name) => (0x1a, 0, name.as_bytes().to_vec()),
            Self::StructField(data) => (0x1a, 0xff, data.clone()),
            Self::Root(name) => (0x1c, 0, name.as_bytes().to_vec()),
            Self::Array(size) => (0x1c, 0x0f, vec![*size]),
            Self::Value(value) => {
                let len = u16::try_from(value.len())
                    .map_err(|_| LedgerError::InvalidInput("EIP-712 field exceeds 65535 bytes"))?;
                let mut data = len.to_be_bytes().to_vec();
                data.extend(value);
                (0x1c, 0xff, data)
            }
        };
        if matches!(self, Self::Value(_)) {
            let count = data.len().div_ceil(255);
            data.chunks(255)
                .enumerate()
                .map(|(index, chunk)| {
                    Apdu::command_with_p2(0xe0, ins, u8::from(index + 1 < count), p2, chunk)
                })
                .collect()
        } else {
            Ok(vec![Apdu::command_with_p2(0xe0, ins, 0, p2, &data)?])
        }
    }
}

impl<T: ApduTransport> LedgerClient<T> {
    pub async fn sign_eip712_hashes(
        &mut self,
        path: &[u32],
        domain: &[u8; 32],
        message: &[u8; 32],
    ) -> Result<EthereumSignature, LedgerError> {
        let mut data = Self::encode_path(path)?;
        data.extend(domain);
        data.extend(message);
        let command = Apdu::command(0xe0, 0x0c, 0, &data)?;
        self.ensure_app("Ethereum").await?;
        self.ready = false;
        self.typed_data_signature(&command).await
    }

    pub async fn sign_eip712(
        &mut self,
        path: &[u32],
        fields: &[Eip712Command],
    ) -> Result<EthereumSignature, LedgerError> {
        let sign = Apdu::command_with_p2(0xe0, 0x0c, 0, 1, &Self::encode_path(path)?)?;
        if fields.is_empty() || fields.len() > 16384 {
            return Err(LedgerError::InvalidInput("invalid EIP-712 command count"));
        }
        let commands = fields
            .iter()
            .map(Eip712Command::encode)
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_app("Ethereum").await?;
        self.ready = false;
        for (index, command) in commands.iter().flatten().enumerate() {
            tracing::debug!(
                index,
                instruction = command[1],
                p2 = command[3],
                bytes = command.len(),
                "Sending Ledger EIP-712 field"
            );
            let response = Apdu::response(self.transport.exchange(command).await?)?;
            if !response.is_empty() {
                return Err(LedgerError::Protocol("unexpected EIP-712 field response"));
            }
        }
        self.typed_data_signature(&sign).await
    }

    async fn typed_data_signature(
        &mut self,
        command: &[u8],
    ) -> Result<EthereumSignature, LedgerError> {
        let response = Apdu::response(self.transport.exchange(command).await?)?;
        if response.len() != 65 {
            return Err(LedgerError::Protocol("invalid EIP-712 signature length"));
        }
        self.ready = true;
        Ok(EthereumSignature {
            v: response[0],
            r: response[1..33].to_vec(),
            s: response[33..].to_vec(),
        })
    }
}
