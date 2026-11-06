use super::{EthereumSignature, LedgerClient};
use crate::protocol::*;
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
            Self::StructName(name) => (INS_ETH_STRUCT, 0, name.as_bytes().to_vec()),
            Self::StructField(data) => (INS_ETH_STRUCT, 0xff, data.clone()),
            Self::Root(name) => (INS_ETH_VALUE, 0, name.as_bytes().to_vec()),
            Self::Array(size) => (INS_ETH_VALUE, 0x0f, vec![*size]),
            Self::Value(value) => {
                let len = u16::try_from(value.len())
                    .map_err(|_| LedgerError::InvalidInput("EIP-712 field exceeds 65535 bytes"))?;
                let mut data = len.to_be_bytes().to_vec();
                data.extend(value);
                (INS_ETH_VALUE, 0xff, data)
            }
        };
        if matches!(self, Self::Value(_)) {
            let count = data.len().div_ceil(APDU_DATA_SIZE);
            data.chunks(APDU_DATA_SIZE)
                .enumerate()
                .map(|(index, chunk)| {
                    Apdu::command_with_p2(CLA_APP, ins, u8::from(index + 1 < count), p2, chunk)
                })
                .collect()
        } else {
            Ok(vec![Apdu::command_with_p2(CLA_APP, ins, 0, p2, &data)?])
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
        let command = Apdu::command(CLA_APP, INS_ETH_TYPED_DATA, 0, &data)?;
        self.ensure_ethereum_app().await?;
        self.ready = false;
        self.typed_data_signature(&command).await
    }

    pub async fn sign_eip712(
        &mut self,
        path: &[u32],
        fields: &[Eip712Command],
    ) -> Result<EthereumSignature, LedgerError> {
        let sign =
            Apdu::command_with_p2(CLA_APP, INS_ETH_TYPED_DATA, 0, 1, &Self::encode_path(path)?)?;
        if fields.is_empty() || fields.len() > 16384 {
            return Err(LedgerError::InvalidInput("invalid EIP-712 command count"));
        }
        let commands = fields
            .iter()
            .map(Eip712Command::encode)
            .collect::<Result<Vec<_>, _>>()?;
        self.ensure_ethereum_app().await?;
        self.ready = false;
        for (index, command) in commands.iter().flatten().enumerate() {
            tracing::debug!(
                index,
                instruction = command[1],
                p2 = command[3],
                bytes = command.len(),
                "Sending Ledger EIP-712 field"
            );
            let response = self.exchange_apdu(command).await?;
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
        let response = self.exchange_apdu(command).await?;
        let signature = EthereumSignature::decode(&response)?;
        self.ready = true;
        Ok(signature)
    }
}
