import Foundation
import HWCoreKitBindings

public enum HWCoreKitError: Error, LocalizedError, Sendable {
    case ble(String)
    case workflow(String)
    case device(String)
    case validation(String)
    case timeout(String)
    case timedOut(operation: String, seconds: TimeInterval)
    case cancelled
    case unknown(String)

    init(hwError: HwCoreError) {
        switch hwError {
        case let .Ble(message):
            self = .ble(message)
        case let .Workflow(message):
            self = .workflow(message)
        case let .Device(message):
            self = .device(message)
        case let .Validation(message):
            self = .validation(message)
        case let .Timeout(message):
            self = .timeout(message)
        case let .Unknown(message):
            self = .unknown(message)
        }
    }

    public var errorDescription: String? {
        switch self {
        case let .ble(message),
            let .workflow(message),
            let .device(message),
            let .validation(message),
            let .timeout(message),
            let .unknown(message):
            return message
        case let .timedOut(operation, seconds):
            return "operation '\(operation)' timed out after \(seconds)s"
        case .cancelled:
            return "operation cancelled"
        }
    }
}

@inline(__always)
func mapError(_ error: Error) -> HWCoreKitError {
    if let walletError = error as? HWCoreKitError {
        return walletError
    }
    if error is CancellationError {
        return .cancelled
    }
    if let hwError = error as? HwCoreError {
        return HWCoreKitError(hwError: hwError)
    }
    return .unknown(String(describing: error))
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
        throw HWCoreKitError.validation(
            "missing Bluetooth privacy usage description. Add NSBluetoothAlwaysUsageDescription to your app Info.plist"
        )
    }
#endif
}
