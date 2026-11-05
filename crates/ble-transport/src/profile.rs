use std::collections::BTreeSet;

use btleplug::api::Characteristic;
use uuid::Uuid;

use crate::{BleError, BleResult};

#[derive(Debug, Clone, Copy)]
pub struct BleProfile {
    pub id: &'static str,
    pub name: &'static str,
    pub service_uuid: Uuid,
    pub write_uuid: Uuid,
    pub notify_uuid: Uuid,
    pub push_uuid: Option<Uuid>,
    pub connection_probe: Option<&'static [u8]>,
    pub write_with_response: bool,
    pub mtu_hint: Option<u16>,
}

impl BleProfile {
    pub const TREZOR_SAFE7: Self = Self {
        id: "trezor_safe7",
        name: "Trezor Safe 7",
        service_uuid: uuid::uuid!("8c000001-a59b-4d58-a9ad-073df69fa1b1"),
        write_uuid: uuid::uuid!("8c000002-a59b-4d58-a9ad-073df69fa1b1"),
        notify_uuid: uuid::uuid!("8c000003-a59b-4d58-a9ad-073df69fa1b1"),
        push_uuid: Some(uuid::uuid!("8c000004-a59b-4d58-a9ad-073df69fa1b1")),
        mtu_hint: Some(244),
        connection_probe: Some(b"Proof of connection"),
        write_with_response: false,
    };

    pub const LEDGER_NANO_X: Self = Self {
        id: "ledger_nano_x",
        name: "Ledger Nano X",
        service_uuid: uuid::uuid!("13d63400-2c97-0004-0000-4c6564676572"),
        notify_uuid: uuid::uuid!("13d63400-2c97-0004-0001-4c6564676572"),
        write_uuid: uuid::uuid!("13d63400-2c97-0004-0002-4c6564676572"),
        push_uuid: None,
        mtu_hint: Some(20),
        connection_probe: None,
        write_with_response: true,
    };

    pub const LEDGER_STAX: Self = Self {
        id: "ledger_stax",
        name: "Ledger Stax",
        service_uuid: uuid::uuid!("13d63400-2c97-6004-0000-4c6564676572"),
        notify_uuid: uuid::uuid!("13d63400-2c97-6004-0001-4c6564676572"),
        write_uuid: uuid::uuid!("13d63400-2c97-6004-0002-4c6564676572"),
        push_uuid: None,
        mtu_hint: Some(20),
        connection_probe: None,
        write_with_response: true,
    };

    pub const LEDGER_FLEX: Self = Self {
        id: "ledger_flex",
        name: "Ledger Flex",
        service_uuid: uuid::uuid!("13d63400-2c97-3004-0000-4c6564676572"),
        notify_uuid: uuid::uuid!("13d63400-2c97-3004-0001-4c6564676572"),
        write_uuid: uuid::uuid!("13d63400-2c97-3004-0002-4c6564676572"),
        push_uuid: None,
        mtu_hint: Some(20),
        connection_probe: None,
        write_with_response: true,
    };

    pub(crate) fn characteristic(
        &self,
        characteristics: &BTreeSet<Characteristic>,
        uuid: Uuid,
        kind: &'static str,
    ) -> BleResult<Characteristic> {
        characteristics
            .iter()
            .find(|c| c.service_uuid == self.service_uuid && c.uuid == uuid)
            .cloned()
            .ok_or(BleError::MissingCharacteristic {
                kind,
                profile: self.id,
            })
    }
}
