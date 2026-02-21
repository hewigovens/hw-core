package uniffi.hwcore

/**
 * Factory for [BleManagerHandle] that works around uniffi 0.31 not generating
 * a Kotlin-level async constructor.  This calls the same FFI entry points that
 * the generated code uses for async methods.
 */
suspend fun BleManagerHandle.Companion.new(): BleManagerHandle {
    return uniffiRustCallAsync(
        UniffiLib.uniffi_hwcore_fn_constructor_blemanagerhandle_new(),
        { future, callback, continuation ->
            UniffiLib.ffi_hwcore_rust_future_poll_u64(future, callback, continuation)
        },
        { future, continuation ->
            UniffiLib.ffi_hwcore_rust_future_complete_u64(future, continuation)
        },
        { future ->
            UniffiLib.ffi_hwcore_rust_future_free_u64(future)
        },
        { FfiConverterTypeBleManagerHandle.lift(it) },
        HwCoreException.ErrorHandler,
    )
}
