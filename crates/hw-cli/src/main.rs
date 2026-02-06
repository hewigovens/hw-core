mod cli;
mod commands;
mod config;
mod pairing;
mod ui;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan(args) => commands::scan::run(args).await,
        Command::Pair(args) => commands::pair::run(args).await,
        Command::Address(args) => commands::address::run(args).await,
        Command::Sign(args) => commands::sign::run(args).await,
    }
}
