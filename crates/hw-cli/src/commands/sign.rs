use anyhow::{bail, Result};

use crate::cli::{SignArgs, SignCommand};

pub async fn run(args: SignArgs) -> Result<()> {
    match args.command {
        SignCommand::Eth(args) => run_eth(args.path, args.tx).await,
    }
}

async fn run_eth(_path: String, _tx: String) -> Result<()> {
    bail!(
        "sign eth is not implemented yet (pending P4: ETH signing flow in /Users/hewig/workspace/h/hw-core/docs/cli-wallet-v1.md)"
    )
}
