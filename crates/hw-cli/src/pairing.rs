use async_trait::async_trait;
use tracing::debug;
use trezor_connect::thp::types::PairingPrompt;
use trezor_connect::thp::{PairingController, PairingDecision, PairingMethod};

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
            println!("  {}. {}{}", idx + 1, method.cli_name(), marker);
        }

        if let Some(nfc_data) = &prompt.nfc_data {
            println!("NFC data from device: {}", hex::encode(nfc_data));
        }

        let chosen = Self::choose_method(&prompt)?;
        debug!("pairing prompt selection: chosen_method={:?}", chosen);
        if chosen != prompt.selected_method {
            debug!("switching pairing method to {:?}", chosen);
            return Ok(PairingDecision::SwitchMethod(chosen));
        }

        let tag = match chosen {
            PairingMethod::QrCode => prompt_nonempty("Enter QR tag (hex): ")?,
            PairingMethod::Nfc => prompt_nonempty("Enter NFC tag (hex): ")?,
            PairingMethod::CodeEntry => {
                let code = prompt_nonempty("Enter 6-digit code shown on Trezor: ")?;
                if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
                    return Err("code entry must be exactly 6 digits".to_string());
                }
                code
            }
            PairingMethod::SkipPairing => {
                return Err("SkipPairing is unsupported in CLI pairing flow".to_string());
            }
        };

        Ok(PairingDecision::SubmitTag {
            method: chosen,
            tag,
        })
    }
}

impl CliPairingController {
    fn choose_method(prompt: &PairingPrompt) -> std::result::Result<PairingMethod, String> {
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

        PairingMethod::from_cli_input(input.trim(), &prompt.available_methods)
            .ok_or_else(|| format!("unsupported pairing method selection '{}'", input.trim()))
    }
}

trait PairingMethodExt: Sized {
    fn from_cli_input(input: &str, available: &[Self]) -> Option<Self>;
    fn cli_name(self) -> &'static str;
}

impl PairingMethodExt for PairingMethod {
    fn from_cli_input(input: &str, available: &[Self]) -> Option<Self> {
        if let Ok(number) = input.parse::<usize>()
            && number > 0
            && number <= available.len()
        {
            return Some(available[number - 1]);
        }

        let parsed = match input.to_ascii_lowercase().as_str() {
            "qr" | "qrcode" | "qr_code" => Self::QrCode,
            "nfc" => Self::Nfc,
            "code" | "codeentry" | "code_entry" => Self::CodeEntry,
            "skip" | "skip_pairing" => Self::SkipPairing,
            _ => return None,
        };
        available.contains(&parsed).then_some(parsed)
    }

    fn cli_name(self) -> &'static str {
        match self {
            Self::QrCode => "qr-code",
            Self::Nfc => "nfc",
            Self::CodeEntry => "code-entry",
            Self::SkipPairing => "skip-pairing",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_method_input_matches_index_or_available_name() {
        let available = [PairingMethod::QrCode, PairingMethod::Nfc];
        for (input, expected) in [
            ("2", Some(PairingMethod::Nfc)),
            ("3", None),
            ("0", None),
            ("QR", Some(PairingMethod::QrCode)),
            ("nfc", Some(PairingMethod::Nfc)),
            ("code", None),
            ("bogus", None),
        ] {
            assert_eq!(
                PairingMethod::from_cli_input(input, &available),
                expected,
                "{input}"
            );
        }
    }
}
