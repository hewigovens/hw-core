mod cli;
mod commands;
mod device;
mod input;
mod logging;
mod output;
mod pairing;
mod ui;

use anyhow::Result;
use clap::Parser;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init_tracing(cli.verbose);

    let skip_pairing = cli.skip_pairing;
    match cli.command {
        Command::Scan(args) => commands::scan::run(args).await,
        Command::Pair(args) => commands::pair::run(args, skip_pairing).await,
        Command::Address(args) => commands::address::run(args, skip_pairing).await,
        Command::Sign(args) => commands::sign::run(args, skip_pairing).await,
        Command::SignMessage(args) => commands::sign_message::run(args, skip_pairing).await,
    }
}
