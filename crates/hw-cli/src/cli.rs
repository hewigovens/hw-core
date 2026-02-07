use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

pub const DEFAULT_ETH_BIP32_PATH: &str = "m/44'/60'/0'/0/0";
pub const DEFAULT_BTC_BIP32_PATH: &str = "m/84'/0'/0'/0/0";

#[derive(Parser, Debug)]
#[command(name = "hw-cli")]
#[command(about = "Interactive Trezor Safe 7 CLI over BLE")]
pub struct Cli {
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,
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
    #[arg(long, default_value_t = 60)]
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
    #[arg(long, alias = "duration-secs", default_value_t = 60)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 60)]
    pub thp_timeout_secs: u64,
    #[arg(long)]
    pub device_id: Option<String>,
    #[arg(long)]
    pub storage_path: Option<PathBuf>,
    #[arg(long)]
    pub host_name: Option<String>,
    #[arg(long, default_value = "hw-core/cli")]
    pub app_name: String,
    #[arg(long, default_value_t = false)]
    pub interactive: bool,
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct AddressArgs {
    #[arg(long, value_enum)]
    pub chain: Option<Chain>,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, default_value_t = true)]
    pub show_on_device: bool,
    #[arg(long, default_value_t = false)]
    pub include_public_key: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    #[arg(long, alias = "duration-secs", default_value_t = 60)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 60)]
    pub thp_timeout_secs: u64,
    #[arg(long)]
    pub device_id: Option<String>,
    #[arg(long)]
    pub storage_path: Option<PathBuf>,
    #[arg(long)]
    pub host_name: Option<String>,
    #[arg(long, default_value = "hw-core/cli")]
    pub app_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Chain {
    Eth,
    Btc,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_defaults_to_ble_and_60s_timeout() {
        let cli = Cli::parse_from(["hw-cli", "pair"]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };

        assert_eq!(cli.verbose, 0);
        assert_eq!(args.pairing_method, PairingMethod::Ble);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert!(!args.interactive);
    }

    #[test]
    fn pair_accepts_duration_secs_alias() {
        let cli = Cli::parse_from(["hw-cli", "pair", "--duration-secs", "45"]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };

        assert_eq!(args.timeout_secs, 45);
    }

    #[test]
    fn pair_accepts_thp_timeout_override() {
        let cli = Cli::parse_from(["hw-cli", "pair", "--thp-timeout-secs", "90"]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };

        assert_eq!(args.thp_timeout_secs, 90);
    }

    #[test]
    fn pair_default_app_name_is_hw_core_cli() {
        let cli = Cli::parse_from(["hw-cli", "pair"]);
        let Command::Pair(args) = cli.command else {
            panic!("expected pair command");
        };

        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn verbose_flag_is_global_and_counted() {
        let cli = Cli::parse_from(["hw-cli", "-vv", "pair"]);
        let Command::Pair(_) = cli.command else {
            panic!("expected pair command");
        };

        assert_eq!(cli.verbose, 2);
    }

    #[test]
    fn address_eth_defaults() {
        let cli = Cli::parse_from(["hw-cli", "address"]);
        let Command::Address(args) = cli.command else {
            panic!("expected address command");
        };

        assert_eq!(args.chain, None);
        assert_eq!(args.path, None);
        assert!(args.show_on_device);
        assert!(!args.include_public_key);
        assert!(!args.chunkify);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn address_accepts_chain_value() {
        let cli = Cli::parse_from(["hw-cli", "address", "--chain", "btc"]);
        let Command::Address(args) = cli.command else {
            panic!("expected address command");
        };
        assert_eq!(args.chain, Some(Chain::Btc));
    }
}
