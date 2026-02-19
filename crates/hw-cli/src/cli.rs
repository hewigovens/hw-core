use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use hw_wallet::chain::Chain;

#[derive(Parser, Debug)]
#[command(name = "hw-cli")]
#[command(about = "Trezor Safe 7 CLI over BLE")]
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
    SignMessage(SignMessageArgs),
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
    #[arg(long)]
    pub force: bool,
}

#[derive(Args, Debug)]
pub struct AddressArgs {
    #[arg(long, value_name = "eth|btc|sol", value_parser = parse_chain_arg)]
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

#[derive(Args, Debug)]
pub struct SignArgs {
    #[command(subcommand)]
    pub command: SignCommand,
}

#[derive(Args, Debug)]
pub struct SignMessageArgs {
    #[command(subcommand)]
    pub command: SignMessageCommand,
}

#[derive(Subcommand, Debug)]
pub enum SignCommand {
    Eth(SignEthArgs),
    Btc(SignBtcArgs),
    Sol(SignSolArgs),
}

#[derive(Subcommand, Debug)]
pub enum SignMessageCommand {
    Eth(SignMessageEthArgs),
    Btc(SignMessageBtcArgs),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum EthSignMessageType {
    Eip191,
    Eip712,
}

#[derive(Args, Debug)]
pub struct SignEthArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub tx: String,
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

#[derive(Args, Debug)]
pub struct SignBtcArgs {
    #[arg(long)]
    pub tx: String,
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

#[derive(Args, Debug)]
pub struct SignSolArgs {
    #[arg(long)]
    pub path: String,
    #[arg(long)]
    pub tx: String,
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

#[derive(Args, Debug)]
pub struct SignMessageEthArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub message: Option<String>,
    #[arg(long = "type", value_enum, default_value_t = EthSignMessageType::Eip191)]
    pub message_type: EthSignMessageType,
    #[arg(long, default_value_t = false)]
    pub hex: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    #[arg(long = "data-file")]
    pub data_file: Option<PathBuf>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    pub metamask_v4_compat: bool,
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

#[derive(Args, Debug)]
pub struct SignMessageBtcArgs {
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long)]
    pub message: String,
    #[arg(long, default_value_t = false)]
    pub hex: bool,
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

fn parse_chain_arg(value: &str) -> Result<Chain, String> {
    value.parse()
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
        assert_eq!(args.chain, Some(Chain::Bitcoin));
    }

    #[test]
    fn address_accepts_solana_chain_value() {
        let cli = Cli::parse_from(["hw-cli", "address", "--chain", "sol"]);
        let Command::Address(args) = cli.command else {
            panic!("expected address command");
        };
        assert_eq!(args.chain, Some(Chain::Solana));
    }

    #[test]
    fn address_rejects_unsupported_chain_value() {
        let result = Cli::try_parse_from(["hw-cli", "address", "--chain", "doge"]);
        assert!(result.is_err());
    }

    #[test]
    fn sign_eth_defaults() {
        let cli = Cli::parse_from([
            "hw-cli",
            "sign",
            "eth",
            "--path",
            "m/44'/60'/0'/0/0",
            "--tx",
            "{\"to\":\"0xdead\"}",
        ]);
        let Command::Sign(args) = cli.command else {
            panic!("expected sign command");
        };
        let SignCommand::Eth(args) = args.command else {
            panic!("expected sign eth command");
        };

        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn sign_sol_defaults() {
        let cli = Cli::parse_from([
            "hw-cli",
            "sign",
            "sol",
            "--path",
            "m/44'/501'/0'/0'",
            "--tx",
            "0x010203",
        ]);
        let Command::Sign(args) = cli.command else {
            panic!("expected sign command");
        };
        let SignCommand::Sol(args) = args.command else {
            panic!("expected sign sol command");
        };

        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn sign_btc_defaults() {
        let cli = Cli::parse_from([
            "hw-cli",
            "sign",
            "btc",
            "--tx",
            "{\"inputs\":[],\"outputs\":[]}",
        ]);
        let Command::Sign(args) = cli.command else {
            panic!("expected sign command");
        };
        let SignCommand::Btc(args) = args.command else {
            panic!("expected sign btc command");
        };

        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn sign_message_eth_defaults() {
        let cli = Cli::parse_from(["hw-cli", "sign-message", "eth", "--message", "hello"]);
        let Command::SignMessage(args) = cli.command else {
            panic!("expected sign-message command");
        };
        let SignMessageCommand::Eth(args) = args.command else {
            panic!("expected sign-message eth command");
        };

        assert_eq!(args.path, None);
        assert_eq!(args.message_type, EthSignMessageType::Eip191);
        assert_eq!(args.message.as_deref(), Some("hello"));
        assert!(!args.hex);
        assert!(!args.chunkify);
        assert!(args.data_file.is_none());
        assert!(args.metamask_v4_compat);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn sign_message_btc_defaults() {
        let cli = Cli::parse_from(["hw-cli", "sign-message", "btc", "--message", "hello"]);
        let Command::SignMessage(args) = cli.command else {
            panic!("expected sign-message command");
        };
        let SignMessageCommand::Btc(args) = args.command else {
            panic!("expected sign-message btc command");
        };

        assert_eq!(args.path, None);
        assert!(!args.hex);
        assert!(!args.chunkify);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }

    #[test]
    fn sign_message_eth_eip712_defaults() {
        let cli = Cli::parse_from([
            "hw-cli",
            "sign-message",
            "eth",
            "--type",
            "eip712",
            "--data-file",
            "/tmp/typed-data.json",
        ]);
        let Command::SignMessage(args) = cli.command else {
            panic!("expected sign-message command");
        };
        let SignMessageCommand::Eth(args) = args.command else {
            panic!("expected sign-message eth command");
        };

        assert_eq!(args.path, None);
        assert_eq!(args.message_type, EthSignMessageType::Eip712);
        assert!(args.message.is_none());
        assert!(args.hex == false);
        assert!(!args.chunkify);
        assert_eq!(
            args.data_file.as_deref(),
            Some(std::path::Path::new("/tmp/typed-data.json"))
        );
        assert!(args.metamask_v4_compat);
        assert_eq!(args.timeout_secs, 60);
        assert_eq!(args.thp_timeout_secs, 60);
        assert_eq!(args.app_name, "hw-core/cli");
    }
}
