use anyhow::{bail, Result};

use crate::cli::{AddressArgs, AddressCommand};

pub async fn run(args: AddressArgs) -> Result<()> {
    match args.command {
        AddressCommand::Eth(args) => run_eth(args.path).await,
    }
}

async fn run_eth(_path: String) -> Result<()> {
    bail!(
        "address eth is not implemented yet (pending P3: ETH address flow in /Users/hewig/workspace/h/hw-core/docs/cli-wallet-v1.md)"
    )
}
