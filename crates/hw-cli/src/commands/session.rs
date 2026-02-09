use anyhow::{bail, Context, Result};
use hw_wallet::bip32::parse_bip32_path;
use hw_wallet::chain::{
    infer_chain_from_path as infer_chain_from_path_wallet, Chain, CHAIN_BTC, CHAIN_ETH,
};
use hw_wallet::eth::{build_sign_tx_request, parse_tx_json, verify_sign_tx_response};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{Context as ReadlineContext, Editor, Helper};
use trezor_connect::thp::{GetAddressRequest, ThpBackend, ThpWorkflow};

use crate::cli::DEFAULT_ETH_BIP32_PATH;

const COMMAND_ADDRESS: &str = "address";
const COMMAND_SIGN: &str = "sign";

const ROOT_COMMANDS: &[&str] = &["help", COMMAND_ADDRESS, COMMAND_SIGN, "exit", "quit"];
const ADDRESS_TOKENS: &[&str] = &[
    CHAIN_ETH,
    CHAIN_BTC,
    "--chain",
    "--path",
    "--show-on-device",
    "--hide-on-device",
    "--include-public-key",
    "--chunkify",
];
const CHAIN_VALUES: &[&str] = &[CHAIN_ETH, CHAIN_BTC];
const SIGN_TOKENS: &[&str] = &[CHAIN_ETH, "--path", "--tx"];

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

pub async fn run<B>(workflow: &mut ThpWorkflow<B>) -> Result<()>
where
    B: ThpBackend + Send,
{
    println!("Interactive session started.");
    println!(
        "Commands: help | address [--chain <eth|btc>] [--path <bip32>] [--hide-on-device] [--include-public-key] [--chunkify] | sign eth --path <bip32> --tx <json|@file> | exit"
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
                    println!("sign eth --path <bip32> --tx <json|@file>");
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
    if words[0] != COMMAND_ADDRESS && words[0] != COMMAND_SIGN {
        return ROOT_COMMANDS.to_vec();
    }

    if words[0] == COMMAND_SIGN {
        if words.last().copied() == Some("--path") && trailing_whitespace {
            return vec![DEFAULT_ETH_BIP32_PATH];
        }
        if words.len() >= 2 && words[words.len() - 2] == "--path" && !trailing_whitespace {
            return Vec::new();
        }
        if words.last().copied() == Some("--tx") && trailing_whitespace {
            return vec!["@./tx.json", "{\"to\":\"0x...\"}"];
        }
        if words.len() >= 2 && words[words.len() - 2] == "--tx" && !trailing_whitespace {
            return Vec::new();
        }
        return SIGN_TOKENS.to_vec();
    }

    if words.last().copied() == Some("--chain") && trailing_whitespace {
        return CHAIN_VALUES.to_vec();
    }
    if words.len() >= 2 && words[words.len() - 2] == "--chain" && !trailing_whitespace {
        return Vec::new();
    }

    if words.last().copied() == Some("--path") && trailing_whitespace {
        let chain = detect_selected_chain(&words).unwrap_or(Chain::Ethereum);
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

async fn handle_line<B>(workflow: &mut ThpWorkflow<B>, line: &str) -> Result<()>
where
    B: ThpBackend + Send,
{
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    match parts[0] {
        COMMAND_ADDRESS => handle_address(workflow, &parts).await,
        COMMAND_SIGN => handle_sign(workflow, &parts).await,
        other => bail!("unknown command '{other}'"),
    }
}

async fn handle_address<B>(workflow: &mut ThpWorkflow<B>, parts: &[&str]) -> Result<()>
where
    B: ThpBackend + Send,
{
    let mut chain: Option<Chain> = None;
    let mut path: Option<&str> = None;
    let mut show_on_device = true;
    let mut include_public_key = false;
    let mut chunkify = false;

    let mut i = 1usize;
    while i < parts.len() {
        match parts[i] {
            CHAIN_ETH => chain = Some(Chain::Ethereum),
            CHAIN_BTC => chain = Some(Chain::Bitcoin),
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
            let path_indices = parse_bip32_path(path)?;
            let inferred = infer_chain_from_path(&path_indices);
            let explicit = chain;
            let chain = explicit.or(inferred).unwrap_or(Chain::Ethereum);
            if let (Some(explicit), Some(inferred)) = (explicit, inferred)
                && explicit != inferred
            {
                bail!(
                    "chain/path mismatch: --chain {:?} conflicts with inferred {:?} from path '{}'",
                    explicit,
                    inferred,
                    path
                );
            }
            (path, chain)
        }
        None => {
            let chain = chain.unwrap_or(Chain::Ethereum);
            (default_path_for_chain(chain), chain)
        }
    };

    if chain == Chain::Bitcoin {
        bail!(
            "BTC address flow is not implemented yet. Use --chain eth or --path {}.",
            DEFAULT_ETH_BIP32_PATH
        );
    }

    let path_indices = parse_bip32_path(path)?;

    let request = GetAddressRequest::ethereum(path_indices)
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

async fn handle_sign<B>(workflow: &mut ThpWorkflow<B>, parts: &[&str]) -> Result<()>
where
    B: ThpBackend + Send,
{
    if parts.get(1).copied() != Some(CHAIN_ETH) {
        bail!("only 'sign eth' is supported");
    }

    let mut path: Option<&str> = None;
    let mut tx_json: Option<String> = None;
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
            "--tx" => {
                i += 1;
                if i >= parts.len() {
                    bail!("missing value for --tx");
                }
                tx_json = Some(parts[i..].join(" "));
                break;
            }
            flag => bail!("unknown flag '{flag}'"),
        }
        i += 1;
    }

    let path = path.ok_or_else(|| anyhow::anyhow!("--path is required"))?;
    let tx_json = tx_json.ok_or_else(|| anyhow::anyhow!("--tx is required"))?;
    let tx_json = if let Some(tx_path) = tx_json.strip_prefix('@') {
        std::fs::read_to_string(tx_path).with_context(|| format!("reading tx file: {tx_path}"))?
    } else {
        tx_json
    };

    let path_indices = parse_bip32_path(path)?;
    let tx = parse_tx_json(&tx_json).context("failed to parse tx JSON")?;
    let request =
        build_sign_tx_request(path_indices, tx).context("failed to build sign request")?;
    let response = workflow
        .sign_tx(request.clone())
        .await
        .context("sign-tx failed")?;

    println!("v: {}", response.v);
    println!("r: 0x{}", hex::encode(&response.r));
    println!("s: 0x{}", hex::encode(&response.s));
    if let Ok(verification) = verify_sign_tx_response(&request, &response) {
        println!("tx_hash: 0x{}", hex::encode(verification.tx_hash));
        println!("recovered_address: {}", verification.recovered_address);
    }
    Ok(())
}

fn default_path_for_chain(chain: Chain) -> &'static str {
    chain.default_path()
}

fn parse_chain(value: &str) -> Result<Chain> {
    value.parse().map_err(anyhow::Error::msg)
}

fn infer_chain_from_path(path: &[u32]) -> Option<Chain> {
    infer_chain_from_path_wallet(path)
}

fn detect_selected_chain(words: &[&str]) -> Option<Chain> {
    let mut i = 1usize;
    let mut chain = None;
    while i < words.len() {
        match words[i] {
            CHAIN_ETH => chain = Some(Chain::Ethereum),
            CHAIN_BTC => chain = Some(Chain::Bitcoin),
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
    use crate::commands::test_support::{
        canned_eth_address_response, canned_eth_sign_response, default_test_host_config,
        MockBackend,
    };
    use hw_wallet::chain::DEFAULT_BTC_BIP32_PATH;
    use trezor_connect::thp::{Chain as ThpChain, ThpWorkflow};

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

    #[test]
    fn sign_completion_suggests_flags() {
        let suggestions = replacements("sign --", "sign --".len());
        assert!(suggestions.contains(&"--path".to_string()));
        assert!(suggestions.contains(&"--tx".to_string()));
    }

    #[tokio::test]
    async fn interactive_handlers_execute_address_then_sign_on_same_workflow() {
        let config = default_test_host_config();
        let backend = MockBackend::autopaired(b"session-test")
            .with_get_address_response(canned_eth_address_response(
                "0x0fA8844c87c5c8017e2C6C3407812A0449dB91dE",
            ))
            .with_sign_tx_response(canned_eth_sign_response());
        let mut workflow = ThpWorkflow::new(backend, config);

        workflow.create_channel().await.unwrap();
        workflow.handshake(false).await.unwrap();

        handle_line(&mut workflow, "address --chain eth")
            .await
            .unwrap();
        handle_line(
            &mut workflow,
            "sign eth --path m/44'/60'/0'/0/0 --tx {\"to\":\"0x000000000000000000000000000000000000dead\"}",
        )
        .await
        .unwrap();

        let backend = workflow.backend_mut();
        assert_eq!(backend.counters.get_address_calls, 1);
        assert_eq!(backend.counters.sign_tx_calls, 1);
        assert_eq!(
            backend.last_get_address_request.as_ref().unwrap().chain,
            ThpChain::Ethereum
        );
        assert_eq!(
            backend.last_sign_tx_request.as_ref().unwrap().chain,
            ThpChain::Ethereum
        );
    }
}
