# hw-core Smoke Matrix

Last updated: 2026-03-10

This is the canonical validation matrix for developer-facing surfaces. If a flow
is not listed here, it is not part of the required smoke gate.

## CLI

| Flow | Command | Environment | Expected result |
|---|---|---|---|
| Help surface | `cargo run -p hw-cli -- --help` | Any dev machine | Help renders without panic |
| Scan | `cargo run -p hw-cli -- -vv scan` | BLE-capable host | Trezor device discovery works |
| Pair | `cargo run -p hw-cli -- -vv pair` | BLE-capable host + device | Pairing reaches paired state |
| ETH address | `cargo run -p hw-cli -- -vv address --chain eth --include-public-key` | Paired device | Address and public key returned |
| ETH sign-tx | `cargo run -p hw-cli -- -vv sign eth --path "m/44'/60'/0'/0/0" --tx '{"to":"0x000000000000000000000000000000000000dead","nonce":"0x0","gas_limit":"0x5208","chain_id":1,"max_fee_per_gas":"0x3b9aca00","max_priority_fee":"0x59682f00","value":"0x0"}'` | Paired device | Signature returned |
| ETH sign-message | `cargo run -p hw-cli -- -vv sign-message eth --message "hello"` | Paired device | Signature returned |

## Apple

| Flow | Command | Environment | Expected result |
|---|---|---|---|
| SDK build | `just bindings` | macOS | Swift bindings sync successfully |
| Sample build (macOS) | `just build-mac-ui` | macOS | macOS sample builds |
| Sample build (iOS) | `just build-ios` | macOS with Xcode | iOS sample builds |
| UI smoke (macOS) | `just test-mac-ui` | macOS | Primary sample controls launch and UI test passes |

## Android

| Flow | Command | Environment | Expected result |
|---|---|---|---|
| Bindings sync | `just build-android` | macOS/Linux with Android SDK | Android library + sample build inputs are generated |
| Sample install/build | `cd android && ./gradlew :sample-app:app:installDebug` | Connected Android device | Debug app installs successfully |
| Runtime smoke | `just run-android` | Connected Android device | App launches and logs are streamable |

## Notes

- Real-device checks still matter for BLE, pairing, reconnect, and signing flows.
- Emulator coverage is useful for protocol regression testing, but it does not replace the smoke matrix above.
- CI should mirror this matrix only where runners can support it reliably.
