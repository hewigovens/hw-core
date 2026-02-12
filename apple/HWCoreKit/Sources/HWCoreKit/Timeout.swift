import Foundation
import HWCoreFFI

func withTimeout<T: Sendable>(
    seconds: TimeInterval?,
    operation: String,
    _ block: @escaping @Sendable () async throws -> T
) async throws -> T {
    guard let seconds else {
        return try await block()
    }

    let durationNs = UInt64(seconds * 1_000_000_000)
    return try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await block() }
        group.addTask {
            try await Task.sleep(nanoseconds: durationNs)
            throw HwCoreError.timedOut(operation: operation, seconds: seconds)
        }

        let result = try await group.next()!
        group.cancelAll()
        return result
    }
}


