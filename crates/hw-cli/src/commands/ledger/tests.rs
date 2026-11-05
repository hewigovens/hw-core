use super::*;
use crate::cli::{Cli, Command};
use clap::Parser;

#[test]
fn ledger_arguments_select_stax_and_keep_trezor_commands_available() {
    let Command::Ledger(args) = Cli::try_parse_from([
        "hw-cli",
        "ledger",
        "--device-id",
        "stax-id",
        "address",
        "--chain-id",
        "137",
    ])
    .unwrap()
    .command
    else {
        panic!("expected Ledger command")
    };
    assert!(matches!(args.model, LedgerModel::Stax));
    assert_eq!(args.device_id.as_deref(), Some("stax-id"));
    assert!(matches!(
        args.command,
        LedgerCommand::Operation(LedgerOperation::Address {
            chain_id: 137,
            no_display: false,
            ..
        })
    ));
    assert!(matches!(
        Cli::try_parse_from(["hw-cli", "scan"]).unwrap().command,
        Command::Scan(_)
    ));
    assert!(Cli::try_parse_from(["hw-cli", "ledger", "--model", "unknown", "scan"]).is_err());
}
