# iOS Manual Validation Matrix

Last updated: 2026-02-18

## Preconditions
- Build and launch the sample app:
  - `just run-ios`
- Test device: Trezor Safe 7 over BLE.
- Storage file path is shown in app logs (`storage path: .../thp-host.json`).

## Matrix

| Scenario | Device state | Host storage state | Steps | Expected result |
| --- | --- | --- | --- | --- |
| First-time pairing | Unlocked | Empty (no static key, no credentials) | `Scan` -> select device -> `Pair Only` -> enter pairing code -> `Connect` | Session phase reaches `Ready`; address/sign buttons enabled; logs include `PAIRING_CODE_REQUIRED` then `SESSION_READY`. |
| Reconnect paired device | Unlocked | Valid static key + credential | Relaunch app -> `Scan` -> `Connect` | No pairing code prompt; session reaches `Ready`; logs show `CONNECT_READY_START` and `SESSION_READY`. |
| Locked device auto-unlock | Locked then unlocked during flow | Valid static key + credential | `Scan` -> `Connect`; unlock device when prompted | Workflow retries handshake/session; session eventually `Ready`; no hard failure on first transient busy/not-ready response. |
| Pairing required after stale credentials | Unlocked | Static key exists but credential invalidated on device | `Scan` -> `Connect` -> pairing prompt appears -> cancel prompt | Status shows pairing required; app remains responsive; `Disconnect` succeeds. |
| Force re-pair | Unlocked | Valid storage | `Scan` -> `Pair Only` (clears storage) -> complete pairing -> `Connect` | Storage is recreated and session reaches `Ready` with fresh credentials. |
| Lifecycle interruption recovery | Unlocked | Any | Connect to device until session exists -> send app to background -> bring app to foreground | App logs lifecycle background disconnect and active recovery; session is re-established or user gets explicit `No devices found for recovery` status. |
| Address request (ETH/BTC/SOL) | Unlocked, session ready | Valid | Select chain -> adjust path/toggles -> `Address` | Address shown in result panel and logs; copy action works. |
| Sign request (ETH) | Unlocked, session ready | Valid | Keep default ETH sample values -> `Sign` -> confirm on device | Signature summary appears; copy/export actions work. |
| Sign request (SOL) | Unlocked, session ready | Valid | Select `SOL` -> use serialized hex -> `Sign` | Signature result appears; logs show successful sign event. |
| Sign request (BTC basic) | Unlocked, session ready | Valid | Select `BTC` -> use sample tx json -> `Sign` | Basic BTC signature flow works for requests that do not require advanced prev-tx/extra-data request types. |

## Negative Cases
- Invalid pairing code format (non-6-digit) should return a validation error and keep session state intact.
- Invalid BTC JSON should fail locally with validation error before transport call.
- Disconnect should clear phase back to `No session` and cancel event stream task.

## Smoke Automation Coverage
- `just test-ios-ui` validates launch, core controls, and scan-button interaction in simulator.
- `just test-mac-ui` validates macOS launch/control accessibility path.
