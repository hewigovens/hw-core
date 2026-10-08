use anyhow::{Context, Result, bail};
use ble_transport::DiscoveredDevice;
use tracing::debug;

use crate::ui::prompt_line;

pub struct DeviceList(pub Vec<DiscoveredDevice>);

impl DeviceList {
    pub fn print(&self) {
        println!("Found {} device(s):", self.0.len());
        for (idx, device) in self.0.iter().enumerate() {
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

    pub fn select(mut self, device_id: Option<&str>) -> Result<DiscoveredDevice> {
        let devices = &mut self.0;
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

        self.print();
        let selected = self.prompt_index()?;
        Ok(self.0.remove(selected))
    }

    fn prompt_index(&self) -> Result<usize> {
        let total = self.0.len();
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
}
