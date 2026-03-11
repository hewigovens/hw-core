import XCTest
@testable import HWCoreKit
import enum HWCoreFFI.HwCoreError

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
