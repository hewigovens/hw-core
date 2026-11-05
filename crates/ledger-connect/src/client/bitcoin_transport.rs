use crate::{ApduTransport, LedgerError, apdu::Apdu};
use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client::Transport,
};
use tokio::sync::Mutex;

pub(super) struct BitcoinTransport<'a, T> {
    state: Mutex<(&'a mut T, usize, u8)>,
}

impl<'a, T> BitcoinTransport<'a, T> {
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            state: Mutex::new((transport, 0, 0)),
        }
    }
}

#[async_trait::async_trait]
impl<T: ApduTransport + Send> Transport for BitcoinTransport<'_, T> {
    type Error = LedgerError;

    async fn exchange(&self, command: &APDUCommand) -> Result<(StatusWord, Vec<u8>), LedgerError> {
        let bytes = Apdu::command_with_p2(
            command.cla,
            command.ins,
            command.p1,
            command.p2,
            &command.data,
        )?;
        let mut state = self.state.lock().await;
        state.1 += 1;
        if command.cla == 0xe1 {
            state.2 = command.ins;
        }
        if state.1 > 100_000 {
            return Err(LedgerError::Protocol("Bitcoin continuation limit exceeded"));
        }
        let mut response = state.0.exchange(&bytes).await?;
        if response.len() < 2 {
            return Err(LedgerError::Protocol("missing Bitcoin status word"));
        }
        let end = response.len() - 2;
        let status = u16::from_be_bytes([response[end], response[end + 1]]);
        if status != 0xe000 && status != 0x9000 {
            return Apdu::response(response).map(|data| (StatusWord::OK, data));
        }
        response.truncate(end);
        // Upstream's message parser indexes byte zero before checking the length.
        // Continuations can be arbitrarily short; only a final message signature is fixed-size.
        if status == 0x9000 && state.2 == 0x10 && response.len() != 65 {
            return Err(LedgerError::Protocol(
                "invalid Bitcoin message signature length",
            ));
        }
        Ok((
            if status == 0xe000 {
                StatusWord::InterruptedExecution
            } else {
                StatusWord::OK
            },
            response,
        ))
    }
}
