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

    @MainActor
    func testWalletSwitchRestrictsLedgerAndRestoresTrezorControls() throws {
        let app = XCUIApplication()
        app.launch()
        let wallet = app.popUpButtons["picker.wallet"]
        XCTAssertTrue(wallet.waitForExistence(timeout: 15))
        let chunkify = app.checkBoxes["toggle.address.chunkify"]
        chunkify.click()
        wallet.click()
        app.menuItems["Ledger Stax"].click()
        XCTAssertTrue(app.radioButtons["BTC"].exists)
        app.radioButtons["BTC"].click()
        XCTAssertTrue(app.textViews["input.sign.btc.tx_json"].exists)
        XCTAssertFalse(app.buttons["button.sign.btc.load_multisig"].isEnabled)
        XCTAssertFalse(app.buttons["button.sign.btc.load_advanced"].isEnabled)
        XCTAssertEqual(app.textFields["input.message.path"].value as? String, "m/84'/0'/0'/0/0")
        XCTAssertTrue(app.radioButtons["SOL"].exists)
        XCTAssertFalse(chunkify.isEnabled)
        let reset = XCTNSPredicateExpectation(predicate: NSPredicate(format: "value == 0"), object: chunkify)
        XCTAssertEqual(XCTWaiter.wait(for: [reset], timeout: 5), .completed)
        XCTAssertFalse(app.buttons["action.pair_only"].isEnabled)
        XCTAssertFalse(app.buttons["action.nonce"].isEnabled)
        app.radioButtons["SOL"].click()
        XCTAssertTrue(app.textFields["input.sign.sol.tx_hex"].exists)
        XCTAssertFalse(app.checkBoxes["toggle.sign.sol.chunkify"].isEnabled)
        XCTAssertEqual(app.textFields["input.message.path"].value as? String, "m/44'/501'/0'/0'")
        app.radioButtons["ETH"].click()
        app.checkBoxes["toggle.message.typed_data"].click()
        XCTAssertTrue(app.textViews["input.message.typed_data"].exists)
        wallet.click()
        app.menuItems["Trezor Safe 7"].click()
        XCTAssertTrue(app.radioButtons["BTC"].exists)
        XCTAssertTrue(app.radioButtons["SOL"].exists)
        XCTAssertTrue(chunkify.isEnabled)
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
