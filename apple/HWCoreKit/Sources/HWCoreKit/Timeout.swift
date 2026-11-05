import Foundation
import HWCoreFFI

private enum TimeoutResult<T: Sendable>: Sendable {
    case value(T)
    case deadline
}

/// The first result observed wins. If the deadline wins, cancellation is sent to the backend (retiring a Ledger session) and even a concurrent successful result is discarded.
func withTimeout<T: Sendable>(
    seconds: TimeInterval?,
    operation: String,
    onCancel: @escaping @Sendable () -> Void = {},
    _ block: @escaping @Sendable () async throws -> T
) async throws -> T {
    if let seconds, !seconds.isFinite || seconds <= 0 || seconds >= Double(UInt64.max) / 1_000_000_000 {
        throw HwCoreError.Validation(message: "Timeout must be a finite positive duration")
    }
    return try await withTaskCancellationHandler {
        try Task.checkCancellation()
        guard let seconds else {
            let result = try await block()
            try Task.checkCancellation()
            return result
        }
        return try await withThrowingTaskGroup(of: TimeoutResult<T>.self) { group in
            defer { group.cancelAll() }
            group.addTask { .value(try await block()) }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return .deadline
            }
            switch try await group.next()! {
            case .value(let result):
                try Task.checkCancellation()
                return result
            case .deadline:
                // UniFFI work must be cancelled before the group waits for its child.
                onCancel()
                throw HwCoreError.timedOut(operation: operation, seconds: seconds)
            }
        }
    } onCancel: {
        onCancel()
    }
}
