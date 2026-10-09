use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ble_transport::{BleManager, BleProfile};
use clap::Args;
use hw_wallet::WalletError;
use hw_wallet::ble::{
    BootstrapTarget, SessionBootstrap, SessionBootstrapOptions, SessionPhase,
    connect_trezor_device, scan_profile_until_match,
};
use tokio::time::timeout;
use tracing::{debug, info};
use trezor_connect::ble::BleBackend;
use trezor_connect::thp::{FileStorage, HostConfig, PairingMethod, ThpWorkflow};

use crate::device::DeviceList;
use crate::pairing::CliPairingController;

const DEFAULT_PEER_REMOVED_HINT: &str =
    "Remove this Trezor from macOS Bluetooth settings, then pair again.";

#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    #[arg(long, alias = "duration-secs", default_value_t = 60)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 60)]
    pub thp_timeout_secs: u64,
    #[arg(long)]
    pub device_id: Option<String>,
    #[arg(long)]
    pub storage_path: Option<PathBuf>,
    #[arg(long)]
    pub host_name: Option<String>,
    #[arg(long, default_value = "hw-core/cli")]
    pub app_name: String,
}

impl ConnectArgs {
    pub fn storage_path(&self) -> PathBuf {
        self.storage_path.clone().unwrap_or_else(|| {
            let home = env::var_os("HOME")
                .or_else(|| env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".hw-core").join("thp-host.json")
        })
    }

    fn host_config(&self, skip_pairing: bool) -> HostConfig {
        let host_name = self.host_name.clone().unwrap_or_else(|| {
            whoami::devicename()
                .ok()
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "hw-core-host".to_string())
        });
        let mut config = HostConfig::new(host_name, self.app_name.clone());
        config.pairing_methods = if skip_pairing {
            vec![PairingMethod::SkipPairing]
        } else {
            vec![PairingMethod::CodeEntry]
        };
        config
    }

    pub async fn open_workflow(
        &self,
        skip_pairing: bool,
        operation_label: &str,
        peer_removed_hint: &str,
    ) -> Result<ThpWorkflow<BleBackend>> {
        let profile = BleProfile::TREZOR_SAFE7;
        let manager = BleManager::new().await.context("BLE manager init failed")?;
        debug!(
            "{} profile: id={}, service_uuid={}",
            operation_label, profile.id, profile.service_uuid
        );

        println!(
            "Scanning for {} devices for {}s...",
            profile.name, self.timeout_secs
        );
        let devices = scan_profile_until_match(
            &manager,
            profile,
            Duration::from_secs(self.timeout_secs),
            self.device_id.as_deref(),
        )
        .await
        .context("BLE scan failed")?;
        info!("scan complete: discovered {} device(s)", devices.len());
        if devices.is_empty() {
            bail!("no devices found");
        }

        let selected = DeviceList(devices).select(self.device_id.as_deref())?;
        let selected_name = selected.info().name.as_deref().unwrap_or("unknown");
        println!(
            "Connecting to {} ({})...",
            selected.info().id,
            selected_name
        );

        println!("Opening BLE session...");
        let session = match timeout(
            Duration::from_secs(self.thp_timeout_secs),
            connect_trezor_device(selected, profile),
        )
        .await
        {
            Err(_) => bail!(
                "opening BLE session timed out after {}s",
                self.thp_timeout_secs
            ),
            Ok(Ok(session)) => session,
            Ok(Err(WalletError::PeerRemovedPairingInfo)) => {
                bail!(
                    "opening BLE session failed: peer removed pairing information. {}",
                    peer_removed_hint
                );
            }
            Ok(Err(err)) => return Err(err).context("opening BLE session failed"),
        };
        println!("BLE session established.");
        debug!("BLE session established");
        let backend = BleBackend::from_session(session, Duration::from_secs(self.thp_timeout_secs));
        debug!(
            "configured THP backend response timeout: {:?}",
            backend.handshake_timeout()
        );

        let storage = Arc::new(FileStorage::new(self.storage_path()));
        let workflow = ThpWorkflow::with_storage(backend, self.host_config(skip_pairing), storage)
            .await
            .context("workflow setup failed")?;
        debug!(
            "{} workflow initialized with persisted host state",
            operation_label
        );

        Ok(workflow)
    }

    pub async fn open_ready_workflow(
        &self,
        skip_pairing: bool,
        operation_label: &str,
    ) -> Result<ThpWorkflow<BleBackend>> {
        let mut workflow = self
            .open_workflow(skip_pairing, operation_label, DEFAULT_PEER_REMOVED_HINT)
            .await?;
        self.prepare_session(&mut workflow, operation_label).await?;
        Ok(workflow)
    }

    async fn prepare_session(
        &self,
        workflow: &mut ThpWorkflow<BleBackend>,
        operation_label: &str,
    ) -> Result<()> {
        println!("Preparing authenticated wallet session...");
        let options = SessionBootstrapOptions {
            thp_timeout: Duration::from_secs(self.thp_timeout_secs),
            try_to_unlock: true,
            ..SessionBootstrapOptions::default()
        };
        loop {
            let step = workflow
                .advance_session_bootstrap(false, BootstrapTarget::Session, &options)
                .await
                .with_context(|| {
                    format!("failed to prepare authenticated wallet session for {operation_label}")
                })?;
            match step {
                SessionPhase::Ready => return Ok(()),
                SessionPhase::NeedsPairingCode => {
                    println!("Pairing required. Complete code-entry pairing on this terminal.");
                    workflow
                        .pairing(Some(&CliPairingController))
                        .await
                        .with_context(|| {
                            format!("pairing failed during {operation_label} workflow")
                        })?;
                }
                other => bail!(
                    "{operation_label} workflow reached unexpected step: {:?}",
                    other
                ),
            }
        }
    }
}
