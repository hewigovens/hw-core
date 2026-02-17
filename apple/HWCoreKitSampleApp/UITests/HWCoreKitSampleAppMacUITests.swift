import XCTest

final class HWCoreKitSampleAppMacUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsPrimaryWorkflowControls() throws {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(waitForElement(app, identifier: "title.app", timeout: 15))
        XCTAssertTrue(waitForElement(app, identifier: "state.session_phase", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "action.scan", fallbackLabel: "Scan", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "action.connect", fallbackLabel: "Connect", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "logs.text", timeout: 10))
    }

    private func waitForElement(
        _ app: XCUIApplication,
        identifier: String,
        fallbackLabel: String? = nil,
        timeout: TimeInterval
    ) -> Bool {
        let byIdentifier = app.descendants(matching: .any)[identifier]
        if byIdentifier.waitForExistence(timeout: timeout) {
            return true
        }

        if let fallbackLabel {
            return app.descendants(matching: .any)[fallbackLabel].waitForExistence(timeout: 2)
        }

        return false
    }
}
