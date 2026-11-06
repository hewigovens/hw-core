use crate::input::read_inline_or_file_argument;
use crate::output::{PrintResponse, print_hex_field, print_labeled_value};
use anyhow::Result;
use clap::Subcommand;
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::eth::TxInput;
use hw_wallet::ledger::{LedgerBitcoinExt, LedgerEthereumExt, LedgerSolanaExt, LedgerTypedDataExt};
use hw_wallet::message::SignTypedDataRequestExt;
use hw_wallet::sol::SolanaSignTxExt;
use ledger_connect::{LedgerBleTransport, LedgerClient};
use trezor_connect::thp::{SignMessageRequest, SignTypedDataRequest, SolanaSignTx};

#[derive(Debug, Subcommand)]
pub(super) enum LedgerOperation {
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

impl LedgerOperation {
    pub(super) async fn run(self, client: &mut LedgerClient<LedgerBleTransport>) -> Result<()> {
        match self {
            Self::BitcoinAddress { path, no_display } => {
                let result = client
                    .bitcoin_address(&parse_bip32_path(&path)?, !no_display)
                    .await?;
                result.print()?;
            }
            Self::SignBitcoinMessage { path, message } => {
                let request =
                    SignMessageRequest::bitcoin(parse_bip32_path(&path)?, message.into_bytes());
                let result = client.sign_verified_bitcoin_message(&request).await?;
                result.print()?;
            }
            Self::SignBitcoinTransaction { tx } => {
                let request = hw_wallet::btc::TxInput::from_json(&read_inline_or_file_argument(
                    &tx,
                    "Bitcoin transaction file",
                )?)?
                .try_into()?;
                let result = client.sign_verified_bitcoin_transaction(&request).await?;
                result.print()?;
            }
            Self::Connect => {
                let app = client.app_info().await?;
                println!("Connected directly to Ledger: {} {}", app.name, app.version);
            }
            Self::SolanaAddress { path, no_display } => {
                let address = client
                    .solana_address(&parse_bip32_path(&path)?, !no_display)
                    .await?;
                print_labeled_value("Address", address);
            }
            Self::SignSolanaTransaction { path, tx } => {
                let bytes = hw_wallet::hex::decode(
                    read_inline_or_file_argument(&tx, "Solana transaction file")?.trim(),
                )?;
                let request = SolanaSignTx::from_serialized_tx(parse_bip32_path(&path)?, bytes)?;
                print_hex_field(
                    "Signature (hex)",
                    &client.sign_verified_solana_transaction(&request).await?,
                );
            }
            Self::SignSolanaMessage { path, message } => {
                let request = SignMessageRequest::solana(parse_bip32_path(&path)?, message, vec![]);
                let result = client.sign_verified_solana_message(&request).await?;
                result.print()?;
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
                result.print()?;
            }
            Self::Address {
                path,
                no_display,
                chain_id,
            } => {
                let address = client
                    .ethereum_address(&parse_bip32_path(&path)?, !no_display, chain_id)
                    .await?;
                print_labeled_value("Address", address.address);
            }
            Self::SignMessage { path, message } => {
                let signature = client
                    .sign_verified_message(&parse_bip32_path(&path)?, message.as_bytes())
                    .await?;
                signature.print()?;
            }
            Self::SignTransaction { path, tx } => {
                let request = TxInput::from_json(&read_inline_or_file_argument(&tx, "tx file")?)?
                    .into_sign_tx(parse_bip32_path(&path)?)?;
                let signature = client.sign_eip1559(&request).await?;
                signature.print()?;
            }
        }
        Ok(())
    }
}
