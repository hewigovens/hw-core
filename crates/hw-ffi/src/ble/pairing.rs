use parking_lot::Mutex;
use trezor_connect::thp::types::PairingPrompt as ThpPairingPrompt;
use trezor_connect::thp::{
    PairingController, PairingDecision, PairingMethod as ThpPairingMethod, Phase, ThpWorkflow,
    ThpWorkflowError,
};

use crate::errors::HWCoreError;
use crate::types::{PairingProgress, PairingProgressKind, PairingPrompt};

struct CodeEntryPairingController {
    code: Mutex<Option<String>>,
}

impl CodeEntryPairingController {
    fn new(code: String) -> Self {
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
        if !prompt
            .available_methods
            .contains(&ThpPairingMethod::CodeEntry)
        {
            return Err("device does not offer code-entry pairing".to_string());
        }

        if prompt.selected_method != ThpPairingMethod::CodeEntry {
            return Ok(PairingDecision::SwitchMethod(ThpPairingMethod::CodeEntry));
        }

        let code = self.code.lock().take().ok_or_else(|| {
            "pairing code already used; submit a fresh code with pairing_submit_code".to_string()
        })?;
        Ok(PairingDecision::SubmitTag {
            method: ThpPairingMethod::CodeEntry,
            tag: code,
        })
    }
}

pub(crate) fn pairing_start_for_state(
    state: &trezor_connect::thp::ThpState,
) -> Result<PairingPrompt, HWCoreError> {
    if state.phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_start requires Pairing phase".to_string(),
        ));
    }

    let methods = state
        .handshake_credentials()
        .map(|credentials| credentials.pairing_methods.clone())
        .or_else(|| {
            state
                .handshake_cache()
                .map(|cache| cache.pairing_methods.clone())
        })
        .unwrap_or_default();
    let message = if state.is_paired() {
        "Connection confirmation is required for this already-paired device".to_string()
    } else if methods.contains(&ThpPairingMethod::CodeEntry) {
        "Enter the 6-digit code shown on the Trezor to finish pairing".to_string()
    } else {
        "Complete pairing on the device to finish connecting".to_string()
    };

    Ok(PairingPrompt {
        available_methods: methods,
        selected_method: state.pairing_method(),
        requires_connection_confirmation: state.is_paired(),
        message,
    })
}

pub(crate) async fn pairing_confirm_connection_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
) -> Result<PairingProgress, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    if workflow.state().phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_confirm_connection requires Pairing phase".to_string(),
        ));
    }
    if !workflow.state().is_paired() {
        return Err(HWCoreError::Validation(
            "device is not in paired-confirmation state; use pairing_submit_code".to_string(),
        ));
    }

    workflow.pairing(None).await.map_err(HWCoreError::from)?;
    Ok(PairingProgress {
        kind: PairingProgressKind::Completed,
        message: "Paired connection confirmed".to_string(),
    })
}

pub(crate) async fn pairing_submit_code_for_workflow<B>(
    workflow: &mut ThpWorkflow<B>,
    code: String,
) -> Result<PairingProgress, HWCoreError>
where
    B: trezor_connect::thp::ThpBackend + Send,
{
    if workflow.state().phase() != Phase::Pairing {
        return Err(HWCoreError::Workflow(
            "pairing_submit_code requires Pairing phase".to_string(),
        ));
    }
    if workflow.state().is_paired() {
        return Err(HWCoreError::Validation(
            "device expects connection confirmation; use pairing_confirm_connection".to_string(),
        ));
    }

    let trimmed = code.trim();
    if trimmed.len() != 6 || !trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(HWCoreError::Validation(
            "pairing code must be exactly 6 digits".to_string(),
        ));
    }

    match workflow
        .submit_code_entry_pairing_tag(trimmed.to_string())
        .await
    {
        Ok(()) => {}
        Err(ThpWorkflowError::PairingInteractionRequired) => {
            let controller = CodeEntryPairingController::new(trimmed.to_string());
            workflow
                .pairing(Some(&controller))
                .await
                .map_err(HWCoreError::from)?;
        }
        Err(err) => return Err(HWCoreError::from(err)),
    }

    Ok(PairingProgress {
        kind: PairingProgressKind::Completed,
        message: "Pairing completed".to_string(),
    })
}
