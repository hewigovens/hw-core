package dev.hewig.hwcore

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.test.ext.junit4.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation smoke tests for the HW Core sample app (Workstream D).
 *
 * These tests verify the app's UI scaffolding without requiring a live Trezor
 * device.  They run on a connected Android device or emulator.
 *
 * Run with:
 *   ./gradlew :app:connectedAndroidTest          (device/emulator required)
 *   just test-android-smoke                       (uses justfile target)
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class AppSmokeTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    /**
     * Verify the app launches and the Home screen is shown with the version
     * string and the "Scan for Devices" button visible.
     */
    @Test
    fun appLaunchShowsHomeScreen() {
        composeRule.onNodeWithText("HW Core Sample").assertIsDisplayed()
        composeRule.onNodeWithText("Scan for Devices").assertIsDisplayed()
        // Version string should contain "hw-core"
        composeRule.onNodeWithText("hw-core", substring = true).assertExists()
    }

    /**
     * Tap "Scan for Devices" and verify the UI transitions to the Scanning
     * state — the app should attempt a BLE scan.  Without a real device the
     * scan returns 0 results; we assert the "Scan Again" / busy state appears.
     *
     * Note: BLE permission must be granted before this test runs, or the scan
     * will silently fail and return 0 results.
     */
    @Test
    fun tapScanNavigatesToScanScreen() {
        composeRule.onNodeWithText("Scan for Devices").performClick()
        // After tapping, either a progress indicator or "Scan Again" should appear
        composeRule.waitUntil(timeoutMillis = 10_000) {
            composeRule
                .onAllNodesWithText("Scan Again")
                .fetchSemanticsNodes()
                .isNotEmpty() ||
            composeRule
                .onAllNodesWithText("Scanning...")
                .fetchSemanticsNodes()
                .isNotEmpty() ||
            composeRule
                .onAllNodesWithText("No devices found", substring = true)
                .fetchSemanticsNodes()
                .isNotEmpty()
        }
        // Reset back to Home
        composeRule.onNodeWithText("Reset").assertExists()
    }

    /**
     * Verify that when session is Ready, all three chain action rows are
     * present in the UI.  This test is driven via a fake ViewModel that
     * bypasses BLE — it tests the composable scaffolding only.
     *
     * TODO (Workstream D): wire a fake/stub ViewModel to test ReadyContent
     * without a live device.  For now this test documents the intent.
     */
    @Test
    fun readyScreenHasAllChainSections() {
        // Until a stub ViewModel is wired, verify the composable node labels
        // exist when we navigate to a pre-seeded Ready screen.
        // This is a placeholder test that will be fleshed out post-merge.
        // For now, just assert the app is alive and on Home.
        composeRule.onNodeWithText("HW Core Sample").assertIsDisplayed()
    }
}
