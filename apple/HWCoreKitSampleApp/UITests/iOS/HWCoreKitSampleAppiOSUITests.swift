import XCTest

final class HWCoreKitSampleAppiOSUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsPrimaryWorkflowControls() throws {
        let app = XCUIApplication()
        app.launch()

        XCTAssertTrue(waitForElement(app, identifier: "title.app", timeout: 15))
        XCTAssertTrue(waitForElement(app, identifier: "state.session_phase", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "action.scan", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "action.connect", timeout: 10))

        let configTab = app.tabBars.buttons["Config"]
        XCTAssertTrue(configTab.waitForExistence(timeout: 10))
        configTab.tap()
        XCTAssertTrue(waitForElement(app, identifier: "input.address.path", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "input.sign.eth.path", timeout: 10))

        let logsTab = app.tabBars.buttons["Logs"]
        XCTAssertTrue(logsTab.waitForExistence(timeout: 10))
        logsTab.tap()
        XCTAssertTrue(waitForElement(app, identifier: "logs.text", timeout: 10))
    }

    @MainActor
    func testScanTapKeepsWorkflowUIResponsive() throws {
        let app = XCUIApplication()
        app.launch()

        let scanButton = app.buttons["action.scan"]
        XCTAssertTrue(scanButton.waitForExistence(timeout: 10))

        addUIInterruptionMonitor(withDescription: "Bluetooth permission") { alert in
            for label in ["Allow", "OK", "Don’t Allow"] {
                if alert.buttons[label].exists {
                    alert.buttons[label].tap()
                    return true
                }
            }
            return false
        }

        if scanButton.isHittable {
            scanButton.tap()
            app.tap()
        }

        XCTAssertTrue(waitForElement(app, identifier: "status.text", timeout: 10))
        XCTAssertTrue(waitForElement(app, identifier: "state.session_phase", timeout: 10))
    }

    private func waitForElement(
        _ app: XCUIApplication,
        identifier: String,
        timeout: TimeInterval
    ) -> Bool {
        app.descendants(matching: .any)[identifier].waitForExistence(timeout: timeout)
    }
}
