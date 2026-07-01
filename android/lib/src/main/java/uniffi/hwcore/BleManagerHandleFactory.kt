package uniffi.hwcore

/** Backward-compatible alias for the UniFFI-generated async factory. */
suspend fun BleManagerHandle.Companion.new(): BleManagerHandle {
    return create()
}
