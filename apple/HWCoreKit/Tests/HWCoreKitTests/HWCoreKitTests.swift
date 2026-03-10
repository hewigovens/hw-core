import XCTest
@testable import HWCoreKit
import enum HWCoreFFI.Chain
import enum HWCoreFFI.HwCoreError

final class HWCoreKitTests: XCTestCase {
    func test_sign_tx_ethereum_helper_populates_request() {
        let request = SignTxRequest.ethereum(
            path: "m/44'/60'/0'/0/7",
            to: "0x000000000000000000000000000000000000dead",
            value: "0x10",
            nonce: "0x2",
            gasLimit: "0x5208",
            chainId: 1,
            data: "0x1234",
            maxFeePerGas: "0x3b9aca00",
            maxPriorityFee: "0x59682f00",
            chunkify: true
        )

        XCTAssertEqual(request.chain, .ethereum)
        XCTAssertEqual(request.path, "m/44'/60'/0'/0/7")
        XCTAssertEqual(request.to, "0x000000000000000000000000000000000000dead")
        XCTAssertEqual(request.value, "0x10")
        XCTAssertEqual(request.nonce, "0x2")
        XCTAssertEqual(request.gasLimit, "0x5208")
        XCTAssertEqual(request.chainId, 1)
        XCTAssertEqual(request.data, "0x1234")
        XCTAssertEqual(request.maxFeePerGas, "0x3b9aca00")
        XCTAssertEqual(request.maxPriorityFee, "0x59682f00")
        XCTAssertTrue(request.chunkify)
    }

    func test_sign_message_bitcoin_helper_populates_request() {
        let request = SignMessageRequest.bitcoin(
            path: "m/84'/0'/0'/0/5",
            message: "hello",
            isHex: true,
            chunkify: true
        )

        XCTAssertEqual(request.chain, .bitcoin)
        XCTAssertEqual(request.path, "m/84'/0'/0'/0/5")
        XCTAssertEqual(request.message, "hello")
        XCTAssertTrue(request.isHex)
        XCTAssertTrue(request.chunkify)
    }

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
