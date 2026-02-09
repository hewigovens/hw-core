use async_trait::async_trait;
use tracing::debug;
use trezor_connect::thp::types::PairingPrompt;
use trezor_connect::thp::{PairingController, PairingDecision, PairingMethod as ThpPairingMethod};

use crate::ui::{prompt_line, prompt_nonempty};

pub struct CliPairingController;

#[async_trait]
impl PairingController for CliPairingController {
    async fn on_prompt(
        &self,
        prompt: PairingPrompt,
    ) -> std::result::Result<PairingDecision, String> {
        debug!(
            "pairing prompt: available_methods={:?}, selected_method={:?}, has_nfc_data={}",
            prompt.available_methods,
            prompt.selected_method,
            prompt.nfc_data.is_some()
        );
        println!();
        println!("Pairing interaction required.");
        println!("Available methods:");
        for (idx, method) in prompt.available_methods.iter().enumerate() {
            let marker = if *method == prompt.selected_method {
                " (selected)"
            } else {
                ""
            };
            println!("  {}. {}{}", idx + 1, method_name(*method), marker);
        }

        if let Some(nfc_data) = &prompt.nfc_data {
            println!("NFC data from device: {}", hex::encode(nfc_data));
        }

        let chosen = choose_pairing_method(&prompt)?;
        debug!("pairing prompt selection: chosen_method={:?}", chosen);
        if chosen != prompt.selected_method {
            debug!("switching pairing method to {:?}", chosen);
            return Ok(PairingDecision::SwitchMethod(chosen));
        }

        let tag = match chosen {
            ThpPairingMethod::QrCode => prompt_nonempty("Enter QR tag (hex): ")?,
            ThpPairingMethod::Nfc => prompt_nonempty("Enter NFC tag (hex): ")?,
            ThpPairingMethod::CodeEntry => {
                let code = prompt_nonempty("Enter 6-digit code shown on Trezor: ")?;
                if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                    return Err("code entry must be exactly 6 digits".to_string());
                }
                code
            }
            ThpPairingMethod::SkipPairing => {
                return Err("SkipPairing is unsupported in interactive CLI flow".to_string());
            }
        };

        Ok(PairingDecision::SubmitTag {
            method: chosen,
            tag,
        })
    }
}

fn choose_pairing_method(prompt: &PairingPrompt) -> std::result::Result<ThpPairingMethod, String> {
    if prompt.available_methods.len() == 1 {
        return Ok(prompt.available_methods[0]);
    }

    let input = prompt_line(&format!(
        "Choose method (1-{}, name, or Enter for selected): ",
        prompt.available_methods.len()
    ))
    .map_err(|e| e.to_string())?;

    if input.trim().is_empty() {
        return Ok(prompt.selected_method);
    }

    parse_pairing_method_input(input.trim(), &prompt.available_methods)
        .ok_or_else(|| format!("unsupported pairing method selection '{}'", input.trim()))
}

fn parse_pairing_method_input(
    input: &str,
    available: &[ThpPairingMethod],
) -> Option<ThpPairingMethod> {
    if let Ok(number) = input.parse::<usize>()
        && number > 0
        && number <= available.len()
    {
        return Some(available[number - 1]);
    }

    let normalized = input.to_ascii_lowercase();
    let parsed = match normalized.as_str() {
        "qr" | "qrcode" | "qr_code" => ThpPairingMethod::QrCode,
        "nfc" => ThpPairingMethod::Nfc,
        "code" | "codeentry" | "code_entry" => ThpPairingMethod::CodeEntry,
        "skip" | "skip_pairing" => ThpPairingMethod::SkipPairing,
        _ => return None,
    };

    if available.contains(&parsed) {
        Some(parsed)
    } else {
        None
    }
}

fn method_name(method: ThpPairingMethod) -> &'static str {
    match method {
        ThpPairingMethod::QrCode => "qr-code",
        ThpPairingMethod::Nfc => "nfc",
        ThpPairingMethod::CodeEntry => "code-entry",
        ThpPairingMethod::SkipPairing => "skip-pairing",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pairing_method_by_index() {
        let available = [ThpPairingMethod::QrCode, ThpPairingMethod::CodeEntry];
        assert_eq!(
            parse_pairing_method_input("2", &available),
            Some(ThpPairingMethod::CodeEntry)
        );
        assert_eq!(parse_pairing_method_input("3", &available), None);
    }

    #[test]
    fn parse_pairing_method_by_name() {
        let available = [ThpPairingMethod::QrCode, ThpPairingMethod::Nfc];
        assert_eq!(
            parse_pairing_method_input("nfc", &available),
            Some(ThpPairingMethod::Nfc)
        );
        assert_eq!(parse_pairing_method_input("code", &available), None);
    }
}
