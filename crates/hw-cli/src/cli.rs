use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::commands::{AddressArgs, PairArgs, ScanArgs, SignArgs, SignMessageArgs};

#[derive(Parser, Debug)]
#[command(name = "hw-cli")]
#[command(about = "Trezor Safe 7 CLI over BLE")]
pub struct Cli {
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,
    /// Skip interactive pairing for headless or emulator-driven runs.
    #[arg(long, global = true, default_value_t = false)]
    pub skip_pairing: bool,
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

impl Cli {
    pub fn init_tracing(&self) {
        let level = match self.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        };
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_thread_names(false)
            .with_thread_ids(false)
            .compact()
            .try_init();
    }

    pub async fn run(self) -> Result<()> {
        let skip_pairing = self.skip_pairing;
        match self.command {
            Command::Scan(args) => args.run().await,
            Command::Pair(args) => args.run(skip_pairing).await,
            Command::Address(args) => args.run(skip_pairing).await,
            Command::Sign(args) => args.run(skip_pairing).await,
            Command::SignMessage(args) => args.run(skip_pairing).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_args_apply_defaults_and_overrides() {
        for (args, timeout_secs, thp_timeout_secs) in [
            (&[][..], 60, 60),
            (&["--duration-secs", "45"], 45, 60),
            (&["--thp-timeout-secs", "90"], 60, 90),
        ] {
            let argv = ["hw-cli", "pair"].into_iter().chain(args.iter().copied());
            let Command::Pair(pair) = Cli::parse_from(argv).command else {
                panic!("expected pair command");
            };
            assert_eq!(pair.connect.timeout_secs, timeout_secs, "{args:?}");
            assert_eq!(pair.connect.thp_timeout_secs, thp_timeout_secs, "{args:?}");
            assert_eq!(pair.connect.app_name, "hw-core/cli");
        }
    }

    #[test]
    fn global_flags_are_accepted_after_the_subcommand() {
        let cli = Cli::parse_from(["hw-cli", "pair", "-vv", "--skip-pairing"]);
        assert_eq!(cli.verbose, 2);
        assert!(cli.skip_pairing);
    }
}
