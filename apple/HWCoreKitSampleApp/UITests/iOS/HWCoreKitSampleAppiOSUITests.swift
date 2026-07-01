import XCTest

final class HWCoreKitSampleAppiOSUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    @MainActor
    func testLaunchShowsPrimaryWorkflowControls() throws {
        let app = launchApp()

        XCTAssertTrue(waitForElement(app, identifier: "title.app", timeout: 15), "Expected title.app")
        XCTAssertTrue(waitForElement(app, identifier: "state.session_phase", timeout: 10), "Expected state.session_phase")
        XCTAssertTrue(waitForElement(app, identifier: "action.scan", timeout: 10), "Expected action.scan")
        XCTAssertTrue(waitForElement(app, identifier: "action.connect", timeout: 10), "Expected action.connect")

        let configTab = app.tabBars.buttons["Config"]
        XCTAssertTrue(configTab.waitForExistence(timeout: 10), "Expected Config tab")
        configTab.tap()
        XCTAssertTrue(waitForElement(app, identifier: "input.address.path", timeout: 10), "Expected input.address.path")
        XCTAssertTrue(waitForElement(app, identifier: "input.sign.eth.path", timeout: 10), "Expected input.sign.eth.path")

        let logsTab = app.tabBars.buttons["Logs"]
        XCTAssertTrue(logsTab.waitForExistence(timeout: 10), "Expected Logs tab")
        logsTab.tap()
        XCTAssertTrue(waitForElement(app, identifier: "logs.text", timeout: 10), "Expected logs.text")
    }

    @MainActor
    func testScanTapKeepsWorkflowUIResponsive() throws {
        let app = launchApp()

        let scanButton = app.buttons["action.scan"]
        XCTAssertTrue(scanButton.waitForExistence(timeout: 10), "Expected action.scan")

        if scanButton.isHittable {
            scanButton.tap()
            dismissBluetoothPermissionIfNeeded(app)
        }

        XCTAssertTrue(waitForElement(app, identifier: "status.text", timeout: 10), "Expected status.text")
        XCTAssertTrue(waitForElement(app, identifier: "state.session_phase", timeout: 10), "Expected state.session_phase")
    }

    private func launchApp() -> XCUIApplication {
        addUIInterruptionMonitor(withDescription: "Bluetooth permission") { [weak self] alert in
            self?.tapFirstMatchingPermissionButton(in: alert) ?? false
        }

        let app = XCUIApplication()
        app.launch()
        dismissBluetoothPermissionIfNeeded(app)
        return app
    }

    private func dismissBluetoothPermissionIfNeeded(_ app: XCUIApplication) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let alert = springboard.alerts.firstMatch
        if alert.waitForExistence(timeout: 2) {
            _ = tapFirstMatchingPermissionButton(in: alert)
            return
        }

        app.tap()
    }

    private func tapFirstMatchingPermissionButton(in alert: XCUIElement) -> Bool {
        for label in ["Allow", "OK", "Don’t Allow", "Don't Allow"] {
            let button = alert.buttons[label]
            if button.exists {
                button.tap()
                return true
            }
        }

        return false
    }

    private func waitForElement(
        _ app: XCUIApplication,
        identifier: String,
        timeout: TimeInterval
    ) -> Bool {
        app.descendants(matching: .any)[identifier].waitForExistence(timeout: timeout)
    }
}
