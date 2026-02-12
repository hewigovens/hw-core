import Foundation
import HWCoreFFI

extension HwCoreError {
    static func timedOut(operation: String, seconds: TimeInterval) -> HwCoreError {
        .Timeout(message: "operation '\(operation)' timed out after \(seconds)s")
    }

    static var cancelled: HwCoreError {
        .Unknown(message: "operation cancelled")
    }
}

@inline(__always)
func mapError(_ error: Error) -> HwCoreError {
    if error is CancellationError {
        return .cancelled
    }
    if let hwError = error as? HwCoreError {
        return hwError
    }
    return .Unknown(message: String(describing: error))
}

func validateBluetoothUsageDescription() throws {
#if os(macOS)
    let keys = [
        "NSBluetoothAlwaysUsageDescription",
        "NSBluetoothPeripheralUsageDescription",
    ]
    let hasUsageDescription = keys.contains { key in
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String else {
            return false
        }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
    if !hasUsageDescription {
        throw HwCoreError.Validation(
            message: "missing Bluetooth privacy usage description. Add NSBluetoothAlwaysUsageDescription to your app Info.plist"
        )
    }
#endif
}
