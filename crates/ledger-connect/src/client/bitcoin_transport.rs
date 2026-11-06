use crate::{ApduTransport, LedgerError, apdu::Apdu, protocol::*};
use ledger_bitcoin_client::{
    apdu::{APDUCommand, StatusWord},
    async_client::Transport,
};
use tokio::sync::Mutex;

const BITCOIN_MESSAGE_SIGNATURE_LENGTH: usize = 65;

pub(super) struct BitcoinTransport<'a, T> {
    state: Mutex<ExchangeState<'a, T>>,
}

struct ExchangeState<'a, T> {
    transport: &'a mut T,
    exchange_count: usize,
    root_instruction: u8,
}

impl<'a, T> BitcoinTransport<'a, T> {
    pub fn new(transport: &'a mut T) -> Self {
        Self {
            state: Mutex::new(ExchangeState {
                transport,
                exchange_count: 0,
                root_instruction: 0,
            }),
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
        state.exchange_count += 1;
        if command.cla == CLA_BITCOIN {
            state.root_instruction = command.ins;
        }
        if state.exchange_count > 100_000 {
            return Err(LedgerError::Protocol("Bitcoin continuation limit exceeded"));
        }
        let (status, response) = Apdu::split_response(state.transport.exchange(&bytes).await?)?;
        if status != STATUS_INTERRUPTED {
            Apdu::check_status(status)?;
        }
        // Upstream's message parser indexes byte zero before checking the length.
        // Continuations can be arbitrarily short; only a final message signature is fixed-size.
        if status == STATUS_OK
            && state.root_instruction == INS_BTC_MESSAGE
            && response.len() != BITCOIN_MESSAGE_SIGNATURE_LENGTH
        {
            return Err(LedgerError::Protocol(
                "invalid Bitcoin message signature length",
            ));
        }
        Ok((
            if status == STATUS_INTERRUPTED {
                StatusWord::InterruptedExecution
            } else {
                StatusWord::OK
            },
            response,
        ))
    }
}
