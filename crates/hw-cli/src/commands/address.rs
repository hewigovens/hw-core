use anyhow::{Context, Result, bail};
use clap::Args;
use hw_wallet::chain::{Chain, ResolvedDerivationPath};
use tracing::info;
use trezor_connect::thp::GetAddressRequest;

use crate::device::ConnectArgs;
use crate::output::{PrintResponse, print_requesting};

#[derive(Args, Debug)]
pub struct AddressArgs {
    #[arg(long, value_name = "eth|btc|sol", value_parser = |value: &str| value.parse::<Chain>())]
    pub chain: Option<Chain>,
    #[arg(long)]
    pub path: Option<String>,
    #[arg(long, default_value_t = true)]
    pub show_on_device: bool,
    #[arg(long, default_value_t = false)]
    pub include_public_key: bool,
    #[arg(long, default_value_t = false)]
    pub chunkify: bool,
    #[command(flatten)]
    pub connect: ConnectArgs,
}

impl AddressArgs {
    pub async fn run(self, skip_pairing: bool) -> Result<()> {
        let resolved = ResolvedDerivationPath::resolve(self.chain, self.path.as_deref())?;
        info!(
            "address command started: chain={:?} path='{}' scan_timeout_secs={} thp_timeout_secs={} show_on_device={} include_public_key={} chunkify={}",
            resolved.chain,
            resolved.path,
            self.connect.timeout_secs,
            self.connect.thp_timeout_secs,
            self.show_on_device,
            self.include_public_key,
            self.chunkify
        );

        let mut workflow = self
            .connect
            .open_ready_workflow(skip_pairing, "address")
            .await?;

        print_requesting(&format!("{:?} address", resolved.chain));
        let response = workflow
            .get_address(self.request(&resolved))
            .await
            .context("get-address failed")?;

        if response.chain != resolved.chain {
            bail!(
                "unexpected response chain: expected {:?}, got {:?}",
                resolved.chain,
                response.chain
            );
        }

        response.print()
    }

    fn request(&self, resolved: &ResolvedDerivationPath) -> GetAddressRequest {
        let path_indices = resolved.path_indices.clone();
        let request = match resolved.chain {
            Chain::Ethereum => GetAddressRequest::ethereum(path_indices),
            Chain::Bitcoin => GetAddressRequest::bitcoin(path_indices),
            Chain::Solana => GetAddressRequest::solana(path_indices),
        };
        request
            .with_show_display(self.show_on_device)
            .with_chunkify(self.chunkify)
            .with_include_public_key(self.include_public_key)
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command};

    #[test]
    fn address_request_carries_resolved_path_and_display_flags() {
        let cli = Cli::parse_from([
            "hw-cli",
            "address",
            "--chain",
            "sol",
            "--include-public-key",
            "--chunkify",
        ]);
        let Command::Address(args) = cli.command else {
            panic!("expected address command");
        };

        let resolved = ResolvedDerivationPath::resolve(args.chain, args.path.as_deref()).unwrap();
        let request = args.request(&resolved);

        assert_eq!(request.chain, Chain::Solana);
        assert_eq!(resolved.path, Chain::Solana.default_path());
        assert_eq!(request.path, resolved.path_indices);
        assert!(request.show_display);
        assert!(request.include_public_key);
        assert!(request.chunkify);
    }

    #[test]
    fn address_chain_flag_accepts_supported_chains_only() {
        for (value, expected) in [
            ("btc", Some(Chain::Bitcoin)),
            ("sol", Some(Chain::Solana)),
            ("doge", None),
        ] {
            let parsed = Cli::try_parse_from(["hw-cli", "address", "--chain", value]);
            let chain = parsed.ok().and_then(|cli| match cli.command {
                Command::Address(args) => args.chain,
                _ => None,
            });
            assert_eq!(chain, expected, "{value}");
        }
    }
}
