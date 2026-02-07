use anyhow::{bail, Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context as ReadlineContext, Editor, Helper};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{GetAddressRequest, ThpWorkflow};

use crate::cli::{Chain, DEFAULT_BTC_BIP32_PATH, DEFAULT_ETH_BIP32_PATH};

const ROOT_COMMANDS: &[&str] = &["help", "address", "exit", "quit"];
const ADDRESS_TOKENS: &[&str] = &[
    "eth",
    "btc",
    "--chain",
    "--path",
    "--show-on-device",
    "--hide-on-device",
    "--include-public-key",
    "--chunkify",
];
const CHAIN_VALUES: &[&str] = &["eth", "btc"];

#[derive(Clone, Default)]
struct ReplHelper;

impl Helper for ReplHelper {}
impl Validator for ReplHelper {}
impl Highlighter for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &ReadlineContext<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        Ok(completion_pairs(line, pos))
    }
}

pub async fn run(workflow: &mut ThpWorkflow<BleBackend>) -> Result<()> {
    println!("Interactive session started.");
    println!(
        "Commands: help | address [--chain <eth|btc>] [--path <bip32>] [--hide-on-device] [--include-public-key] [--chunkify] | exit"
    );

    let mut editor = build_editor()?;

    loop {
        match editor.readline("hw-cli> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                let _ = editor.add_history_entry(line);

                if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
                    break;
                }
                if line.eq_ignore_ascii_case("help") {
                    println!(
                        "address [--chain <eth|btc>] [--path <bip32>] [--hide-on-device] [--include-public-key] [--chunkify]"
                    );
                    println!("exit");
                    continue;
                }

                if let Err(err) = handle_line(workflow, line).await {
                    eprintln!("Error: {err:#}");
                }
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(err) => return Err(err).context("failed to read interactive input"),
        }
    }

    Ok(())
}

fn build_editor() -> Result<Editor<ReplHelper, DefaultHistory>> {
    let mut editor = Editor::<ReplHelper, DefaultHistory>::new()
        .context("failed to initialize interactive editor")?;
    editor.set_helper(Some(ReplHelper));
    Ok(editor)
}

fn completion_pairs(line: &str, pos: usize) -> (usize, Vec<Pair>) {
    let (start, token) = current_token(line, pos);
    let mut pairs: Vec<Pair> = completion_candidates(line, pos)
        .into_iter()
        .filter(|candidate| candidate.starts_with(token))
        .map(|candidate| Pair {
            display: candidate.to_string(),
            replacement: candidate.to_string(),
        })
        .collect();
    pairs.sort_by(|lhs, rhs| lhs.replacement.cmp(&rhs.replacement));
    pairs.dedup_by(|lhs, rhs| lhs.replacement == rhs.replacement);
    (start, pairs)
}

fn completion_candidates(line: &str, pos: usize) -> Vec<&'static str> {
    let prefix = &line[..pos];
    let words: Vec<&str> = prefix.split_whitespace().collect();
    let trailing_whitespace = prefix
        .chars()
        .last()
        .map(char::is_whitespace)
        .unwrap_or(false);

    if words.is_empty() {
        return ROOT_COMMANDS.to_vec();
    }
    if words[0] != "address" {
        return ROOT_COMMANDS.to_vec();
    }

    if words.last().copied() == Some("--chain") && trailing_whitespace {
        return CHAIN_VALUES.to_vec();
    }
    if words.len() >= 2 && words[words.len() - 2] == "--chain" && !trailing_whitespace {
        return Vec::new();
    }

    if words.last().copied() == Some("--path") && trailing_whitespace {
        let chain = detect_selected_chain(&words).unwrap_or(Chain::Eth);
        return vec![default_path_for_chain(chain)];
    }
    if words.len() >= 2 && words[words.len() - 2] == "--path" && !trailing_whitespace {
        return Vec::new();
    }

    ADDRESS_TOKENS.to_vec()
}

fn current_token(line: &str, pos: usize) -> (usize, &str) {
    let prefix = &line[..pos];
    let trailing_whitespace = prefix
        .chars()
        .last()
        .map(char::is_whitespace)
        .unwrap_or(false);
    if trailing_whitespace {
        return (pos, "");
    }

    let start = prefix.rfind(char::is_whitespace).map_or(0, |idx| idx + 1);
    (start, &prefix[start..])
}

async fn handle_line(workflow: &mut ThpWorkflow<BleBackend>, line: &str) -> Result<()> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    if parts[0] != "address" {
        bail!("unknown command '{}'", parts[0]);
    }
    let mut chain: Option<Chain> = None;
    let mut path: Option<&str> = None;
    let mut show_on_device = true;
    let mut include_public_key = false;
    let mut chunkify = false;

    let mut i = 1usize;
    while i < parts.len() {
        match parts[i] {
            "eth" => chain = Some(Chain::Eth),
            "btc" => chain = Some(Chain::Btc),
            "--chain" => {
                i += 1;
                let value = parts
                    .get(i)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("missing value for --chain"))?;
                chain = Some(parse_chain(value)?);
            }
            "--path" => {
                i += 1;
                let value = parts
                    .get(i)
                    .copied()
                    .ok_or_else(|| anyhow::anyhow!("missing value for --path"))?;
                path = Some(value);
            }
            "--show-on-device" => show_on_device = true,
            "--hide-on-device" => show_on_device = false,
            "--include-public-key" => include_public_key = true,
            "--chunkify" => chunkify = true,
            flag => bail!("unknown flag '{flag}'"),
        }
        i += 1;
    }

    let (path, chain) = match path {
        Some(path) => {
            let address_n = parse_bip32_path(path)?;
            let inferred = infer_chain_from_address_n(&address_n);
            let explicit = chain;
            let chain = explicit.or(inferred).unwrap_or(Chain::Eth);
            if let (Some(explicit), Some(inferred)) = (explicit, inferred) {
                if explicit != inferred {
                    bail!(
                        "chain/path mismatch: --chain {:?} conflicts with inferred {:?} from path '{}'",
                        explicit,
                        inferred,
                        path
                    );
                }
            }
            (path, chain)
        }
        None => {
            let chain = chain.unwrap_or(Chain::Eth);
            (default_path_for_chain(chain), chain)
        }
    };

    if chain == Chain::Btc {
        bail!(
            "BTC address flow is not implemented yet. Use --chain eth or --path {}.",
            DEFAULT_ETH_BIP32_PATH
        );
    }

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

fn default_path_for_chain(chain: Chain) -> &'static str {
    match chain {
        Chain::Eth => DEFAULT_ETH_BIP32_PATH,
        Chain::Btc => DEFAULT_BTC_BIP32_PATH,
    }
}

fn parse_chain(value: &str) -> Result<Chain> {
    match value {
        "eth" | "ethereum" => Ok(Chain::Eth),
        "btc" | "bitcoin" => Ok(Chain::Btc),
        _ => bail!("unsupported chain '{}'; expected eth or btc", value),
    }
}

fn infer_chain_from_address_n(address_n: &[u32]) -> Option<Chain> {
    const HARDENED_MASK: u32 = 0x8000_0000;
    const COIN_BTC: u32 = 0;
    const COIN_ETH: u32 = 60;

    let coin_type = address_n.get(1).copied()? & !HARDENED_MASK;
    match coin_type {
        COIN_ETH => Some(Chain::Eth),
        COIN_BTC => Some(Chain::Btc),
        _ => None,
    }
}

fn detect_selected_chain(words: &[&str]) -> Option<Chain> {
    let mut i = 1usize;
    let mut chain = None;
    while i < words.len() {
        match words[i] {
            "eth" => chain = Some(Chain::Eth),
            "btc" => chain = Some(Chain::Btc),
            "--chain" => {
                if let Some(value) = words.get(i + 1).copied() {
                    chain = parse_chain(value).ok();
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacements(line: &str, pos: usize) -> Vec<String> {
        let (_, pairs) = completion_pairs(line, pos);
        pairs.into_iter().map(|pair| pair.replacement).collect()
    }

    #[test]
    fn root_completion_suggests_commands() {
        let suggestions = replacements("ad", 2);
        assert_eq!(suggestions, vec!["address".to_string()]);
    }

    #[test]
    fn address_completion_suggests_chain_and_flags() {
        let suggestions = replacements("address ", "address ".len());
        assert!(suggestions.contains(&"--chain".to_string()));
        assert!(suggestions.contains(&"eth".to_string()));
    }

    #[test]
    fn address_completion_suggests_flags() {
        let suggestions = replacements("address --sh", "address --sh".len());
        assert_eq!(suggestions, vec!["--show-on-device".to_string()]);
    }

    #[test]
    fn path_completion_suggests_default_eth_path() {
        let suggestions = replacements("address --path ", "address --path ".len());
        assert_eq!(suggestions, vec![DEFAULT_ETH_BIP32_PATH.to_string()]);
    }

    #[test]
    fn path_completion_suggests_default_btc_path_when_chain_selected() {
        let suggestions = replacements(
            "address --chain btc --path ",
            "address --chain btc --path ".len(),
        );
        assert_eq!(suggestions, vec![DEFAULT_BTC_BIP32_PATH.to_string()]);
    }
}
