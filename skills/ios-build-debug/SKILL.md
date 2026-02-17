---
name: ios-build-debug
description: "Build, run, and debug Apple sample apps with a repeatable artifact loop: launch app, capture logs, capture screenshot, inspect accessibility output, and report UI regressions. Use when a user asks to run iOS/macOS sample apps, verify simulator screenshots, gather console logs, or automate taps/clicks in debug sessions." 
---

# iOS Build Debug

## Overview
Use this skill to produce deterministic artifacts for Apple UI debugging: build/run result, logs, screenshot, and optional accessibility tree.

## iOS Workflow
1. Run:
```bash
scripts/capture_ios_debug.sh /path/to/repo
```
2. Collect paths from stdout: `LOG_FILE`, `SCREENSHOT`, `UI_DUMP`, `UDID`.
3. Review screenshot and UI tree (`AXFrame` should match full device size).
4. For interaction, use AXe with accessibility identifiers:
```bash
axe tap --udid "$UDID" --id action.scan
axe tap --udid "$UDID" --id action.connect
```

## macOS Workflow (AXe Fallback)
AXe does not automate macOS apps. Use the macOS script for logs + screenshot:
```bash
scripts/capture_macos_debug.sh /path/to/repo
```
This emits `LOG_FILE`, `SCREENSHOT`, `RUN_LOG`, and `APP_PID`.

For basic interaction, use AppleScript UI scripting (requires Accessibility permission for Terminal/Codex):
```bash
osascript -e 'tell application "System Events" to click button "Scan" of window 1 of process "HWCoreKitSampleApp"'
```

For robust macOS automation, prefer XCTest UI tests with accessibility identifiers.

## Reporting
Always return:
1. Build/run status.
2. Artifact paths.
3. UI verdict (`expected` or `unexpected`) and specific mismatch list.
4. Relevant log lines tied to the mismatch.
