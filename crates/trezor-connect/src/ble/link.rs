use std::time::Duration;

use ble_transport::BleLink;
use tokio::time;
use tracing::{debug, trace};
use trezor_thp::ChannelIO;
use trezor_thp::channel::buffered::Buffered;
use trezor_thp::channel::{MAX_RETRANSMISSION_COUNT, PacketInResult, retransmit_after_ms};
use trezor_thp::error::TransportError;

use super::channel::{OpenChannel, PumpChannel};
use super::device_prompts::DevicePrompts;
use crate::thp::backend::{BackendError, BackendResult};
use crate::thp::proto::{ButtonAck, ButtonRequestProto, Cancel, WireMessage};
use crate::thp::types::CancelHandle;

pub(super) const SESSION_ID: u8 = 0;
const MAX_BUSY_BACKOFF_MS: u64 = 500;

fn can_retransmit(retry: Option<u8>) -> bool {
    retry.is_some_and(|r| r.saturating_add(1) < MAX_RETRANSMISSION_COUNT)
}

/// Packet I/O for the THP pump; `recv_packet` returns `None` when `wait` elapses.
#[allow(async_fn_in_trait)]
pub(super) trait PacketLink {
    async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()>;
    async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>>;

    async fn flush<C: ChannelIO>(&mut self, channel: &mut Buffered<C>) -> BackendResult<()> {
        while channel.packet_out_ready() {
            let packet = channel.packet_out()?;
            self.send_packet(&packet).await?;
        }
        Ok(())
    }

    /// Sends pending packets and feeds incoming ones until `done` holds, retransmitting unacked messages.
    async fn pump<C: PumpChannel>(
        &mut self,
        channel: &mut Buffered<C>,
        response_timeout: Duration,
        done: impl FnMut(&Buffered<C>, &PacketInResult) -> bool,
    ) -> BackendResult<()> {
        self.pump_cancellable(channel, response_timeout, done, None)
            .await
            .map(drop)
    }

    /// Like [`PacketLink::pump`], but returns `Ok(false)` when `cancel` is requested.
    ///
    /// Cancellation is only observed while waiting for the next packet, so the channel never
    /// holds a half-processed packet or an unconsumed message when this returns `false`.
    async fn pump_cancellable<C: PumpChannel>(
        &mut self,
        channel: &mut Buffered<C>,
        response_timeout: Duration,
        mut done: impl FnMut(&Buffered<C>, &PacketInResult) -> bool,
        cancel: Option<&CancelHandle>,
    ) -> BackendResult<bool> {
        loop {
            self.flush(channel).await?;
            let retry = channel.retry_count();
            let wait = retry.map_or(response_timeout, |r| {
                Duration::from_millis(retransmit_after_ms(r).into())
            });
            let received = match cancel {
                Some(cancel) => tokio::select! {
                    biased;
                    packet = self.recv_packet(wait) => packet?,
                    () = cancel.requested() => return Ok(false),
                },
                None => self.recv_packet(wait).await?,
            };
            let Some(packet) = received else {
                if !can_retransmit(retry) {
                    return Err(BackendError::TransportTimeout);
                }
                channel.message_retransmit()?;
                continue;
            };
            let result = channel.packet_in(&packet);
            match &result {
                PacketInResult::TransportError {
                    error: TransportError::TransportBusy,
                } if can_retransmit(retry) => {
                    let backoff = rand::random_range(0..MAX_BUSY_BACKOFF_MS);
                    debug!("THP transport busy; resending in {backoff}ms");
                    time::sleep(Duration::from_millis(backoff)).await;
                    channel.message_retransmit()?;
                    continue;
                }
                PacketInResult::TransportError { error } => return Err((*error).into()),
                PacketInResult::Failed { error } => return Err((*error).into()),
                PacketInResult::Ignored { .. } => trace!("THP ignored packet"),
                _ => {}
            }
            if done(channel, &result) {
                self.flush(channel).await?;
                return Ok(true);
            }
        }
    }

    /// Reads the next device message, announcing and acknowledging any ButtonRequest on the way.
    ///
    /// While the device waits for the user, a cancel request sends `Cancel` on the open channel
    /// (as Suite does); the device then answers the pending request with a `Failure`. A prompt
    /// left open past `timeout` is cancelled the same way and its answer drained, so the call
    /// fails with `TransportTimeout` without leaving a late response for the next request.
    async fn receive_message(
        &mut self,
        channel: &mut OpenChannel,
        timeout: Duration,
        prompts: &DevicePrompts,
    ) -> BackendResult<(u16, Vec<u8>)> {
        let mut prompting = false;
        let mut timed_out = false;
        loop {
            if prompting {
                let outcome = self.await_prompt(channel, timeout, prompts).await?;
                if outcome != PromptOutcome::Answered {
                    prompts.cancel.clear();
                    timed_out |= outcome == PromptOutcome::TimedOut;
                    debug!(?outcome, "THP device prompt not answered; sending Cancel");
                    channel.message_in(SESSION_ID, Cancel::MESSAGE_TYPE, &[])?;
                    prompting = false;
                    continue;
                }
            } else {
                self.pump(channel, timeout, |_, result| result.got_message())
                    .await?;
            }
            // trezor-thp queues the ACK when the message is consumed, so flush after message_out.
            let (_session, message_type, payload) = channel.message_out()?;
            trace!(message_type, len = payload.len(), "THP receive");
            if message_type != ButtonRequestProto::MESSAGE_TYPE {
                self.flush(channel).await?;
                if timed_out {
                    return Err(BackendError::TransportTimeout);
                }
                return Ok((message_type, payload));
            }
            debug!("THP ButtonRequest; sending ButtonAck");
            prompts.announce(&payload);
            channel.message_in(SESSION_ID, ButtonAck::MESSAGE_TYPE, &[])?;
            prompting = true;
        }
    }

    /// Waits on a device prompt until the device answers, the user cancels, or `timeout` passes.
    async fn await_prompt(
        &mut self,
        channel: &mut OpenChannel,
        timeout: Duration,
        prompts: &DevicePrompts,
    ) -> BackendResult<PromptOutcome> {
        // Cancel can only be sent once the device has acknowledged the ButtonAck.
        let mut got_message = false;
        self.pump(channel, timeout, |channel, result| {
            got_message |= result.got_message();
            got_message || channel.retry_count().is_none()
        })
        .await?;
        if got_message {
            return Ok(PromptOutcome::Answered);
        }
        match self
            .pump_cancellable(
                channel,
                timeout,
                |_, result| result.got_message(),
                Some(&prompts.cancel),
            )
            .await
        {
            Ok(true) => Ok(PromptOutcome::Answered),
            Ok(false) => Ok(PromptOutcome::Cancelled),
            Err(BackendError::TransportTimeout) => Ok(PromptOutcome::TimedOut),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PromptOutcome {
    Answered,
    Cancelled,
    TimedOut,
}

impl PacketLink for BleLink {
    async fn send_packet(&mut self, packet: &[u8]) -> BackendResult<()> {
        Ok(self.write(packet).await?)
    }

    async fn recv_packet(&mut self, wait: Duration) -> BackendResult<Option<Vec<u8>>> {
        match time::timeout(wait, self.read()).await {
            Ok(packet) => Ok(Some(packet?)),
            Err(_) => Ok(None),
        }
    }
}
