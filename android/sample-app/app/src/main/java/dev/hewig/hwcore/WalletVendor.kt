package dev.hewig.hwcore

import uniffi.hwcore.*

enum class WalletVendor(val label: String, val ledgerModel: LedgerModel?) {
    TREZOR("Trezor Safe 7", null),
    STAX("Ledger Stax", LedgerModel.STAX),
    NANO_X("Ledger Nano X", LedgerModel.NANO_X),
    FLEX("Ledger Flex", LedgerModel.FLEX);

    val isLedger: Boolean get() = ledgerModel != null
}
