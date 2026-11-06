use super::command::LedgerOperation;
use crate::device::DeviceList;
use anyhow::{Result, bail};
use ble_transport::BleManager;
use clap::{Args, Subcommand};
use hw_wallet::ledger::LedgerModel;
use ledger_connect::{LedgerBleTransport, LedgerClient};
use std::time::Duration;

#[derive(Debug, Args)]
pub struct LedgerArgs {
    /// Ledger model: nano-x, stax, or flex.
    #[arg(long, default_value = "stax")]
    model: LedgerModel,
    /// Exact device ID from `ledger scan`; required when several devices are visible.
    #[arg(long)]
    device_id: Option<String>,
    #[arg(long, default_value_t = 5)]
    scan_secs: u64,
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    #[command(subcommand)]
    command: LedgerCommand,
}

#[derive(Debug, Subcommand)]
enum LedgerCommand {
    Scan,
    #[command(flatten)]
    Operation(LedgerOperation),
}

impl LedgerArgs {
    pub async fn run(self) -> Result<()> {
        if self.timeout_secs == 0 || self.scan_secs == 0 {
            bail!("scan and operation timeouts must be positive");
        }
        let profile = self.model.profile();
        let manager = BleManager::new().await?;
        let devices = manager
            .scan_profile(profile, Duration::from_secs(self.scan_secs))
            .await?;
        let command = match self.command {
            LedgerCommand::Scan => {
                if devices.is_empty() {
                    println!(
                        "No Ledger devices found. Enable Bluetooth and unlock your Ledger, then retry."
                    );
                } else {
                    DeviceList(devices).print();
                }
                return Ok(());
            }
            LedgerCommand::Operation(command) => command,
        };
        let devices: Vec<_> = devices
            .into_iter()
            .filter(|device| {
                self.device_id
                    .as_ref()
                    .is_none_or(|id| device.info().id == *id)
            })
            .collect();
        if devices.len() != 1 {
            bail!(
                "expected one Ledger device, found {}; use ledger scan and --device-id",
                devices.len()
            );
        }
        let device = DeviceList(devices).select(None)?;
        let operation_timeout = Duration::from_secs(self.timeout_secs);
        let session = tokio::time::timeout(operation_timeout, device.connect(profile)).await??;
        let transport = LedgerBleTransport::new(session, operation_timeout).await?;
        let mut client = LedgerClient::new(transport);
        let result = command.run(&mut client).await;
        let disconnect = client.into_transport().disconnect().await;
        result?;
        disconnect?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
