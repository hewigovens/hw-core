use parking_lot::Mutex;
use trezor_connect::thp::types::PairingPrompt as ThpPairingPrompt;
use trezor_connect::thp::{PairingController, PairingDecision, PairingMethod};

pub(super) struct CodeEntryPairingController {
    code: Mutex<Option<String>>,
}

impl CodeEntryPairingController {
    pub(super) fn new(code: String) -> Self {
        Self {
            code: Mutex::new(Some(code)),
        }
    }
}

#[async_trait::async_trait]
impl PairingController for CodeEntryPairingController {
    async fn on_prompt(
        &self,
        prompt: ThpPairingPrompt,
    ) -> std::result::Result<PairingDecision, String> {
        if !prompt.available_methods.contains(&PairingMethod::CodeEntry) {
            return Err("device does not offer code-entry pairing".to_string());
        }

        if prompt.selected_method != PairingMethod::CodeEntry {
            return Ok(PairingDecision::SwitchMethod(PairingMethod::CodeEntry));
        }

        let code = self.code.lock().take().ok_or_else(|| {
            "pairing code already used; submit a fresh code with pairing_submit_code".to_string()
        })?;
        Ok(PairingDecision::SubmitTag {
            method: PairingMethod::CodeEntry,
            tag: code,
        })
    }
}
