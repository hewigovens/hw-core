package dev.hewig.hwcore

import uniffi.hwcore.*

sealed class SampleDevice {
    abstract fun info(): BleDeviceInfo
    class Trezor(val handle: BleDiscoveredDevice) : SampleDevice() {
        override fun info() = handle.info()
    }
    class Ledger(val handle: LedgerDiscoveredDevice) : SampleDevice() {
        override fun info() = handle.info()
    }
}
