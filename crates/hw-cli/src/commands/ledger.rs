use std::time::Duration;

use crate::input::read_inline_or_file_argument;
use anyhow::{Result, bail};
use ble_transport::{BleManager, BleProfile};
use clap::{Args, Subcommand, ValueEnum};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::eth::TxInput;
use hw_wallet::ledger::{
    LedgerBitcoinExt, LedgerEthereumExt, LedgerSigningResult, LedgerSolanaExt, LedgerTypedDataExt,
};
use hw_wallet::message::SignTypedDataRequestExt;
use hw_wallet::sol::SolanaSignTxExt;
use ledger_connect::{LedgerBleTransport, LedgerClient};
use trezor_connect::thp::{SignMessageRequest, SignTypedDataRequest, SolanaSignTx};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LedgerModel {
    NanoX,
    Stax,
    Flex,
}

impl LedgerModel {
    fn profile(self) -> BleProfile {
        match self {
            Self::NanoX => ledger_connect::LedgerModel::NanoX.profile(),
            Self::Stax => ledger_connect::LedgerModel::Stax.profile(),
            Self::Flex => ledger_connect::LedgerModel::Flex.profile(),
        }
    }
}

#[derive(Debug, Args)]
pub struct LedgerArgs {
    #[arg(long, value_enum, default_value = "stax")]
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
    /// Retrieve and verify a standard Bitcoin address (BIP44/49/84/86).
    BitcoinAddress {
        #[arg(long, default_value = "m/84'/0'/0'/0/0")]
        path: String,
        #[arg(long)]
        no_display: bool,
    },
    /// Sign a Bitcoin message and verify the recovered key (BIP137).
    SignBitcoinMessage {
        #[arg(long, default_value = "m/84'/0'/0'/0/0")]
        path: String,
        #[arg(long)]
        message: String,
    },
    /// Sign BIP84 transaction JSON with full ref_txs, without broadcasting.
    SignBitcoinTransaction {
        #[arg(long)]
        tx: String,
    },
    /// Retrieve a Solana address, displaying it by default.
    SolanaAddress {
        #[arg(long, default_value = "m/44'/501'/0'/0'")]
        path: String,
        #[arg(long)]
        no_display: bool,
    },
    /// Sign serialized Solana message bytes (legacy or v0), without broadcasting.
    SignSolanaTransaction {
        #[arg(long, default_value = "m/44'/501'/0'/0'")]
        path: String,
        #[arg(long)]
        tx: String,
    },
    /// Sign UTF-8 text in the Solana OCMS v1 envelope.
    SignSolanaMessage {
        #[arg(long, default_value = "m/44'/501'/0'/0'")]
        path: String,
        #[arg(long)]
        message: String,
    },
    /// Stream full EIP-712 JSON for review, or explicitly sign precomputed hashes.
    SignTypedData {
        #[arg(long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
        #[arg(long, conflicts_with_all = ["domain_separator_hash", "message_hash"], required_unless_present = "domain_separator_hash")]
        data: Option<String>,
        #[arg(long, requires = "message_hash")]
        domain_separator_hash: Option<String>,
        #[arg(long, requires = "domain_separator_hash")]
        message_hash: Option<String>,
    },
    Scan,
    /// Connect and report the active app without requesting a signature.
    Connect,
    /// Retrieve an Ethereum address, displaying it on the device by default.
    Address {
        #[arg(long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
        #[arg(long)]
        no_display: bool,
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
    },
    /// Sign an EIP-191 personal message (UTF-8).
    SignMessage {
        #[arg(long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
        #[arg(long)]
        message: String,
    },
    /// Sign an EIP-1559 transaction from JSON or @file, without broadcasting.
    SignTransaction {
        #[arg(long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
        #[arg(long)]
        tx: String,
    },
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
        if matches!(self.command, LedgerCommand::Scan) {
            if devices.is_empty() {
                println!(
                    "No Ledger devices found. Enable Bluetooth and unlock your Ledger, then retry."
                );
            }
            for device in devices {
                let info = device.info();
                println!(
                    "{}  {}",
                    info.id,
                    info.name.as_deref().unwrap_or(profile.name)
                );
            }
            return Ok(());
        }
        let mut devices: Vec<_> = devices
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
        let device = devices
            .pop()
            .ok_or_else(|| anyhow::anyhow!("Ledger not found"))?;
        let operation_timeout = Duration::from_secs(self.timeout_secs);
        let session = tokio::time::timeout(operation_timeout, device.connect(profile)).await??;
        let transport = LedgerBleTransport::new(session, operation_timeout).await?;
        let mut client = LedgerClient::new(transport);
        let result = self.command.run(&mut client).await;
        let disconnect = client.into_transport().disconnect().await;
        result?;
        disconnect?;
        Ok(())
    }
}

impl LedgerCommand {
    async fn run(self, client: &mut LedgerClient<LedgerBleTransport>) -> Result<()> {
        match self {
            Self::BitcoinAddress { path, no_display } => {
                let result = client
                    .bitcoin_address(&parse_bip32_path(&path)?, !no_display)
                    .await?;
                println!(
                    "address={}\npublic_key={}",
                    result.address,
                    hex::encode(result.public_key)
                );
            }
            Self::SignBitcoinMessage { path, message } => {
                let request =
                    SignMessageRequest::bitcoin(parse_bip32_path(&path)?, message.into_bytes());
                let result = client.sign_verified_bitcoin_message(&request).await?;
                let formatted = hw_wallet::message::NormalizedMessageSignature::from(&result);
                println!("address={}\nsignature={}", result.address, formatted.value);
            }
            Self::SignBitcoinTransaction { tx } => {
                let request = hw_wallet::btc::TxInput::from_json(&read_inline_or_file_argument(
                    &tx,
                    "Bitcoin transaction file",
                )?)?
                .try_into()?;
                let result = client.sign_verified_bitcoin_transaction(&request).await?;
                for (index, signature) in result.signatures.iter().enumerate() {
                    println!("signature[{index}]={}", hex::encode(signature));
                }
                println!(
                    "signed_transaction={}\ntransaction_id={}",
                    hex::encode(result.serialized_transaction),
                    result.transaction_id
                );
            }
            Self::Scan => {}
            Self::Connect => {
                let app = client.app_info().await?;
                println!("Connected directly to Ledger: {} {}", app.name, app.version);
            }
            Self::SolanaAddress { path, no_display } => {
                let key = client
                    .solana_public_key(&parse_bip32_path(&path)?, !no_display)
                    .await?;
                println!("{}", bs58::encode(key).into_string());
            }
            Self::SignSolanaTransaction { path, tx } => {
                let bytes = hw_wallet::hex::decode(
                    read_inline_or_file_argument(&tx, "Solana transaction file")?.trim(),
                )?;
                let request = SolanaSignTx::from_serialized_tx(parse_bip32_path(&path)?, bytes)?;
                println!(
                    "signature={}",
                    hex::encode(client.sign_verified_solana_transaction(&request).await?)
                );
            }
            Self::SignSolanaMessage { path, message } => {
                let request = SignMessageRequest::solana(parse_bip32_path(&path)?, message, vec![]);
                let result = client.sign_verified_solana_message(&request).await?;
                println!(
                    "address={}\nsignature={}",
                    result.address,
                    hex::encode(result.signature)
                );
                if let Some(bytes) = result.signed_data {
                    println!("signed_data={}", hex::encode(bytes));
                }
            }
            Self::SignTypedData {
                path,
                data,
                domain_separator_hash,
                message_hash,
            } => {
                let json = data
                    .map(|data| read_inline_or_file_argument(&data, "typed data file"))
                    .transpose()?;
                let request = SignTypedDataRequest::from_eip712(
                    parse_bip32_path(&path)?,
                    json.as_deref(),
                    domain_separator_hash.as_deref(),
                    message_hash.as_deref(),
                    true,
                )?;
                let result = client.sign_verified_typed_data(&request).await?;
                println!(
                    "address={}\nsignature=0x{}",
                    result.address,
                    hex::encode(result.signature)
                );
            }
            Self::Address {
                path,
                no_display,
                chain_id,
            } => {
                let address = client
                    .ethereum_address(&parse_bip32_path(&path)?, !no_display, chain_id)
                    .await?;
                println!("{}", address.address);
            }
            Self::SignMessage { path, message } => {
                let signature = client
                    .sign_verified_message(&parse_bip32_path(&path)?, message.as_bytes())
                    .await?;
                Self::print_signature(signature);
            }
            Self::SignTransaction { path, tx } => {
                let request = TxInput::from_json(&read_inline_or_file_argument(&tx, "tx file")?)?
                    .into_sign_tx(parse_bip32_path(&path)?)?;
                let signature = client.sign_eip1559(&request).await?;
                Self::print_signature(signature);
            }
        }
        Ok(())
    }

    fn print_signature(signature: LedgerSigningResult) {
        println!("recovered_address={}", signature.recovered_address);
        println!("signing_hash=0x{}", hex::encode(&signature.signing_hash));
        println!(
            "v={} r=0x{} s=0x{}",
            signature.v,
            hex::encode(&signature.r),
            hex::encode(&signature.s)
        );
        if let Some(transaction) = signature.signed_transaction {
            println!("signed_transaction=0x{}", hex::encode(transaction));
        } else {
            let mut bytes = signature.r;
            bytes.extend_from_slice(&signature.s);
            bytes.push(signature.v);
            println!("signature=0x{}", hex::encode(bytes));
        }
        if let Some(hash) = signature.transaction_hash {
            println!("transaction_hash=0x{}", hex::encode(hash));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Command};
    use clap::Parser;

    #[test]
    fn ledger_arguments_select_stax_and_keep_trezor_commands_available() {
        let Command::Ledger(args) = Cli::try_parse_from([
            "hw-cli",
            "ledger",
            "--device-id",
            "stax-id",
            "address",
            "--chain-id",
            "137",
        ])
        .unwrap()
        .command
        else {
            panic!("expected Ledger command")
        };
        assert!(matches!(args.model, LedgerModel::Stax));
        assert_eq!(args.device_id.as_deref(), Some("stax-id"));
        assert!(matches!(
            args.command,
            LedgerCommand::Address {
                chain_id: 137,
                no_display: false,
                ..
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["hw-cli", "scan"]).unwrap().command,
            Command::Scan(_)
        ));
        assert!(Cli::try_parse_from(["hw-cli", "ledger", "--model", "unknown", "scan"]).is_err());
    }
}
