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
