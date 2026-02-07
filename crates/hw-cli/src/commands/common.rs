use anyhow::{bail, Context, Result};
use ble_transport::{BleProfile, DiscoveredDevice};
use tracing::debug;

use crate::ui::prompt_line;

pub fn trezor_profile() -> Result<BleProfile> {
    BleProfile::trezor_safe7()
        .ok_or_else(|| anyhow::anyhow!("binary was built without the trezor-safe7 BLE profile"))
}

pub fn select_device(
    mut devices: Vec<DiscoveredDevice>,
    device_id: Option<&str>,
) -> Result<DiscoveredDevice> {
    debug!(
        "select_device: candidates={}, device_id_filter={:?}",
        devices.len(),
        device_id
    );
    if let Some(query) = device_id {
        if let Some(idx) = devices.iter().position(|d| d.info().id == query) {
            debug!("select_device: exact match for device_id={}", query);
            return Ok(devices.remove(idx));
        }

        let matches: Vec<usize> = devices
            .iter()
            .enumerate()
            .filter(|(_, device)| device.info().id.contains(query))
            .map(|(idx, _)| idx)
            .collect();

        if matches.len() == 1 {
            debug!(
                "select_device: partial match for device_id={} resolved to index={}",
                query, matches[0]
            );
            return Ok(devices.remove(matches[0]));
        }

        if matches.is_empty() {
            bail!("no scanned device matched --device-id '{}'", query);
        }
        bail!(
            "--device-id '{}' matched multiple devices; use a full id",
            query
        );
    }

    if devices.len() == 1 {
        return Ok(devices.remove(0));
    }

    println!("Multiple devices found:");
    for (idx, device) in devices.iter().enumerate() {
        let info = device.info();
        println!(
            "  {}. id={} name={} rssi={}",
            idx + 1,
            info.id,
            info.name.as_deref().unwrap_or("unknown"),
            info.rssi
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }

    let selected = prompt_device_selection(devices.len())?;
    Ok(devices.remove(selected))
}

pub fn print_discovered_devices(devices: &[DiscoveredDevice]) {
    println!("Found {} device(s):", devices.len());
    for (idx, device) in devices.iter().enumerate() {
        let info = device.info();
        println!(
            "  {}. id={} name={} rssi={}",
            idx + 1,
            info.id,
            info.name.as_deref().unwrap_or("unknown"),
            info.rssi
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
}

fn prompt_device_selection(total: usize) -> Result<usize> {
    loop {
        let input = prompt_line("Select device number: ")?;
        let number = input
            .parse::<usize>()
            .with_context(|| format!("invalid selection '{}'", input))?;
        if number == 0 || number > total {
            println!("Please enter a number between 1 and {}.", total);
            continue;
        }
        return Ok(number - 1);
    }
}
