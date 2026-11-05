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

    @MainActor
    func testWalletSwitchRestrictsLedgerAndRestoresTrezorChains() throws {
        let app = launchApp()
        let wallet = app.buttons["picker.wallet"]
        XCTAssertTrue(wallet.waitForExistence(timeout: 10))
        wallet.tap()
        let ledger = app.buttons["Ledger Stax"]
        XCTAssertTrue(ledger.waitForExistence(timeout: 5))
        ledger.tap()
        XCTAssertTrue(app.buttons["BTC"].exists)
        XCTAssertTrue(app.buttons["SOL"].exists)
        XCTAssertFalse(app.buttons["action.pair_only"].isEnabled)
        wallet.tap()
        app.buttons["Trezor Safe 7"].tap()
        XCTAssertTrue(app.buttons["BTC"].exists)
        XCTAssertTrue(app.buttons["SOL"].exists)
    }

    @MainActor
    func testTypedDataEditorAndSolanaInputs() throws {
        let app = launchApp()
        app.tabBars.buttons["Config"].tap()
        let typed = app.switches["toggle.message.typed_data"]
        for _ in 0..<5 where !typed.isHittable { app.swipeUp() }
        XCTAssertTrue(typed.exists)
        typed.tap()
        XCTAssertTrue(app.textViews["input.message.typed_data"].exists)
        app.tabBars.buttons["Wallet"].tap()
        app.buttons["SOL"].tap()
        app.tabBars.buttons["Config"].tap()
        XCTAssertTrue(app.textFields["input.sign.sol.tx_hex"].exists)
        XCTAssertFalse(app.switches["toggle.message.typed_data"].exists)
    }

    private func launchApp() -> XCUIApplication {
        addUIInterruptionMonitor(withDescription: "Bluetooth permission") { [weak self] alert in
            self?.tapFirstMatchingPermissionButton(in: alert) ?? false
        }

        let app = XCUIApplication()
        app.launch()
        waitForBootstrapOrBluetoothPermission(app)
        dismissBluetoothPermissionIfNeeded(app)
        return app
    }

    // Bootstrap's BLE init shows the Bluetooth alert at an unpredictable time, swallowing taps made meanwhile.
    private func waitForBootstrapOrBluetoothPermission(_ app: XCUIApplication) {
        let alert = XCUIApplication(bundleIdentifier: "com.apple.springboard").alerts.firstMatch
        let status = app.descendants(matching: .any)["status.text"]
        let ready = XCTNSPredicateExpectation(
            predicate: NSPredicate { _, _ in
                alert.exists || (status.exists && (status.value as? String).map { $0 != "Idle" } == true)
            },
            object: nil
        )
        _ = XCTWaiter.wait(for: [ready], timeout: 30)
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
