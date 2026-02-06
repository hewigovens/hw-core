use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "hw-cli")]
#[command(about = "Interactive Trezor Safe 7 CLI over BLE")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Scan(ScanArgs),
    Pair(PairArgs),
    Address(AddressArgs),
    Sign(SignArgs),
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[arg(long, default_value_t = 5)]
    pub duration_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum PairingMethod {
    Ble,
}

#[derive(Args, Debug)]
pub struct PairArgs {
    #[arg(long, value_enum, default_value_t = PairingMethod::Ble)]
    pub pairing_method: PairingMethod,
    #[arg(long, alias = "duration-secs", default_value_t = 30)]
    pub timeout_secs: u64,
    #[arg(long)]
    pub device_id: Option<String>,
    #[arg(long)]
    pub storage_path: Option<PathBuf>,
    #[arg(long)]
    pub host_name: Option<String>,
    #[arg(long, default_value = "hw-cli")]
    pub app_name: String,
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct AddressArgs {
    #[command(subcommand)]
    pub command: AddressCommand,
}

#[derive(Subcommand, Debug)]
pub enum AddressCommand {
    Eth(AddressEthArgs),
}

#[derive(Args, Debug)]
pub struct AddressEthArgs {
    #[arg(long)]
    pub path: String,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    #[command(subcommand)]
    pub command: SignCommand,
}

#[derive(Subcommand, Debug)]
pub enum SignCommand {
    Eth(SignEthArgs),
}

#[derive(Args, Debug)]
pub struct SignEthArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub tx: String,
}
