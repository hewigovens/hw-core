use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{GetAddressRequest, ThpWorkflow};

pub async fn run(workflow: &mut ThpWorkflow<BleBackend>) -> Result<()> {
    println!("Interactive session started.");
    println!("Commands: help | address eth --path <bip32> [--show-on-device] [--include-public-key] [--chunkify] | exit");

    let stdin = io::stdin();
    loop {
        print!("hw-cli> ");
        io::stdout().flush().context("failed to flush stdout")?;

        let mut line = String::new();
        let read = stdin.read_line(&mut line).context("failed to read stdin")?;
        if read == 0 {
            println!();
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
            break;
        }
        if line.eq_ignore_ascii_case("help") {
            println!(
                "address eth --path <bip32> [--show-on-device] [--include-public-key] [--chunkify]"
            );
            println!("exit");
            continue;
        }

        if let Err(err) = handle_line(workflow, line).await {
            eprintln!("Error: {err:#}");
        }
    }

    Ok(())
}

async fn handle_line(workflow: &mut ThpWorkflow<BleBackend>, line: &str) -> Result<()> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    if parts[0] != "address" {
        bail!("unknown command '{}'", parts[0]);
    }
    if parts.get(1).copied() != Some("eth") {
        bail!("only 'address eth' is supported");
    }

    let mut path: Option<&str> = None;
    let mut show_on_device = false;
    let mut include_public_key = false;
    let mut chunkify = false;

    let mut i = 2usize;
    while i < parts.len() {
        match parts[i] {
            "--path" => {
                i += 1;
                let value = parts
                    .get(i)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("missing value for --path"))?;
                path = Some(value);
            }
            "--show-on-device" => show_on_device = true,
            "--include-public-key" => include_public_key = true,
            "--chunkify" => chunkify = true,
            flag => bail!("unknown flag '{flag}'"),
        }
        i += 1;
    }

    let path = path.ok_or_else(|| anyhow::anyhow!("--path is required"))?;
    let address_n = parse_bip32_path(path)?;

    let request = GetAddressRequest::ethereum(address_n)
        .with_show_display(show_on_device)
        .with_include_public_key(include_public_key)
        .with_chunkify(chunkify);
    let response = workflow
        .get_address(request)
        .await
        .context("get-address failed")?;

    println!("Address: {}", response.address);
    if let Some(mac) = response.mac {
        println!("MAC: {}", hex::encode(mac));
    }
    if let Some(public_key) = response.public_key {
        println!("Public key: {}", public_key);
    }

    Ok(())
}
