import XCTest
@testable import HWCoreKit
import HWCoreFFI

final class HWCoreKitTests: XCTestCase {
    func test_redacted_masks_short_and_long_values() {
        XCTAssertEqual(redacted("short"), "***")
        XCTAssertEqual(redacted("12345678901"), "123456...8901")
    }

    func test_map_error_preserves_hwcore_error_variants() {
        let error = HwCoreError.Validation(message: "bad input")

        XCTAssertEqual(mapError(error), error)
    }

    func test_map_error_maps_cancellation_to_cancelled() {
        XCTAssertEqual(
            mapError(CancellationError()),
            HwCoreError.Unknown(message: "operation cancelled")
        )
    }

    func test_with_timeout_returns_result_before_deadline() async throws {
        let value = try await withTimeout(seconds: 0.2, operation: "unit-test") {
            try await Task.sleep(nanoseconds: 10_000_000)
            return "ok"
        }

        XCTAssertEqual(value, "ok")
    }

    func test_with_timeout_throws_timeout_error() async {
        await XCTAssertThrowsErrorAsync(
            try await withTimeout(seconds: 0.01, operation: "unit-test") {
                try await Task.sleep(nanoseconds: 100_000_000)
                return "late"
            }
        ) { error in
            XCTAssertEqual(
                error as? HwCoreError,
                HwCoreError.Timeout(message: "operation 'unit-test' timed out after 0.01s")
            )
        }
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ handler: (Error) -> Void
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw")
    } catch {
        handler(error)
    }
}

// Models a foreign async operation that ignores Task cancellation until explicitly stopped.
private final class ForeignOperation: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?
    private var stopped = false

    func run() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if stopped { lock.unlock(); continuation.resume(); return }
            self.continuation = continuation
            lock.unlock()
        }
    }

    func cancel() {
        lock.lock()
        stopped = true
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume()
    }
}

extension HWCoreKitTests {
    func test_timeout_stops_foreign_work_before_waiting_for_task_group() async {
        let foreign = ForeignOperation()
        // Bound the pre-fix failure so this regression test cannot hang forever.
        let fallback = Task { try? await Task.sleep(nanoseconds: 500_000_000); foreign.cancel() }
        defer { fallback.cancel() }
        let start = ContinuousClock.now
        do {
            try await withTimeout(seconds: 0.02, operation: "foreign", onCancel: { foreign.cancel() }) {
                await foreign.run()
            }
            XCTFail("Expected timeout")
        } catch {
            XCTAssertEqual(error as? HwCoreError, .Timeout(message: "operation 'foreign' timed out after 0.02s"))
        }
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(300))
    }

    func test_cancellation_stops_foreign_work_without_a_deadline() async {
        let foreign = ForeignOperation()
        let fallback = Task { try? await Task.sleep(nanoseconds: 500_000_000); foreign.cancel() }
        defer { fallback.cancel() }
        let start = ContinuousClock.now
        let task = Task {
            try await withTimeout(seconds: nil, operation: "foreign", onCancel: { foreign.cancel() }) {
                await foreign.run()
            }
        }
        await Task.yield()
        task.cancel()
        do { try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(300))
    }
}

private final class BackendProbe: @unchecked Sendable {
    let operation = ForeignOperation()
    private let lock = NSLock()
    private var disconnects = 0
    private var cancellations = 0
    var disconnectCount: Int { lock.withLock { disconnects } }
    var cancellationCount: Int { lock.withLock { cancellations } }
    func disconnect() { lock.withLock { disconnects += 1 } }
    func cancel() {
        lock.withLock { cancellations += 1 }
        operation.cancel()
    }
}

private final class FakeLedgerSession: LedgerSessionHandle, @unchecked Sendable {
    let probe = BackendProbe()
    override func cancel() { probe.cancel() }
    override func disconnect() async throws { probe.disconnect() }
    override func sessionState() async throws -> SessionState {
        await probe.operation.run()
        return SessionState(phase: .ready, canPairOnly: false, canConnect: false, canGetAddress: true, canSignTx: true, requiresPairingCode: false, promptMessage: nil)
    }
}

private final class FakeTrezorWorkflow: BleWorkflowHandle, @unchecked Sendable {
    let probe = BackendProbe()
    override func cancel() { probe.cancel() }
    override func abort() async throws { probe.disconnect() }
    override func sessionState() async throws -> SessionState {
        await probe.operation.run()
        return SessionState(phase: .ready, canPairOnly: false, canConnect: false, canGetAddress: true, canSignTx: true, requiresPairingCode: false, promptMessage: nil)
    }
}

extension HWCoreKitTests {
    private func fakeSessions() -> [(WalletSession, BackendProbe)] {
        let ledger = FakeLedgerSession(noHandle: .init())
        let trezor = FakeTrezorWorkflow(noHandle: .init())
        return [
            (WalletSession(ledger: ledger, logger: nil, retryPolicy: sessionRetryPolicyDefault()), ledger.probe),
            (WalletSession(workflow: trezor, logger: nil, retryPolicy: sessionRetryPolicyDefault()), trezor.probe),
        ]
    }

    func test_disconnect_from_cancelled_task_reaches_both_backends() async {
        for (session, probe) in fakeSessions() {
            for timeout: TimeInterval? in [nil, 0.2] {
                await Task {
                    withUnsafeCurrentTask { $0?.cancel() }
                    XCTAssertTrue(Task.isCancelled)
                    await session.disconnect(timeout: timeout)
                }.value
            }
            XCTAssertEqual(probe.disconnectCount, 2)
        }
    }

    func test_session_timeout_cancels_foreign_work_for_both_backends() async {
        for (session, probe) in fakeSessions() {
            let fallback = Task { try? await Task.sleep(nanoseconds: 500_000_000); probe.operation.cancel() }
            defer { fallback.cancel() }
            let start = ContinuousClock.now
            do {
                _ = try await session.sessionState(timeout: 0.02)
                XCTFail("Expected timeout")
            } catch {
                XCTAssertEqual(error as? HwCoreError, .Timeout(message: "operation 'sessionState' timed out after 0.02s"))
            }
            XCTAssertEqual(probe.cancellationCount, 1)
            XCTAssertLessThan(start.duration(to: .now), .milliseconds(300))
        }
    }
}
