mod cli;
mod commands;
mod device;
mod input;
mod output;
mod pairing;
mod ui;

use anyhow::Result;
use clap::Parser;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    cli.init_tracing();
    cli.run().await
}
