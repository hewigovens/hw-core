# hw-core Roadmap

Last updated: 2026-10-07

This is the single planning document for hw-core. It stays high level; concrete work items are tracked as [GitHub issues](https://github.com/hewigovens/hw-core/issues), and past work is in git history.

## Product Goal

Ship a stable, reusable host stack for hardware-wallet communication over THP/BLE that external developers can integrate through Rust, CLI, and FFI (Swift/Kotlin) surfaces without reverse-engineering behavior from sample apps or source code.

"Developer ready" means:
- Core wallet flows (scan, pair, reconnect, address, sign-tx, sign-message) succeed reliably on supported platforms.
- Public request/response behavior is stable, documented, and covered by tests.
- Android and Apple consumers have a supported, packaged integration path, not just sample apps.
- CI and the [smoke matrix](smoke-matrix.md) prove the flows we claim to support.

## Current Status

The THP/BLE stack works end to end against Trezor Safe 7: discovery, pairing, session establishment, encrypted messaging, and persisted pairing state. `hw-wallet` provides shared orchestration for the CLI and `hw-ffi`, which generates Swift and Kotlin bindings used by the Apple and Android sample apps. Emulator CI runs against firmware core v2.12.5.

| Capability | Ethereum | Bitcoin | Solana |
|---|---|---|---|
| Address retrieval | Done | Done | Done |
| Transaction signing | Partial: no network/token definitions ([#99](https://github.com/hewigovens/hw-core/issues/99)) | Partial: output script-type validation ([#101](https://github.com/hewigovens/hw-core/issues/101)); SLIP-24 not validated on hardware ([#102](https://github.com/hewigovens/hw-core/issues/102)) | Partial: no `additional_info` for token transfers ([#100](https://github.com/hewigovens/hw-core/issues/100)) |
| Message signing | Done (EIP-191 + EIP-712) | Done | Not planned |

## Milestones

| Milestone | Status | Exit criteria | Issues |
|---|---|---|---|
| M1: Protocol-complete baseline | In progress | Supported ETH/BTC/SOL flows match Trezor Suite request shapes; THP transport is built on the official `trezor-thp` crate; consumer input validation is consistent across entry points | [#98](https://github.com/hewigovens/hw-core/issues/98), [#99](https://github.com/hewigovens/hw-core/issues/99), [#100](https://github.com/hewigovens/hw-core/issues/100), [#101](https://github.com/hewigovens/hw-core/issues/101), [#103](https://github.com/hewigovens/hw-core/issues/103), [#104](https://github.com/hewigovens/hw-core/issues/104) |
| M2: Consumer-ready SDK surfaces | In progress | Android and Apple developers can integrate hw-core from versioned, published artifacts using written guides | [#109](https://github.com/hewigovens/hw-core/issues/109), [#110](https://github.com/hewigovens/hw-core/issues/110), [#111](https://github.com/hewigovens/hw-core/issues/111), [#112](https://github.com/hewigovens/hw-core/issues/112) |
| M3: Release confidence | In progress | CI, the smoke matrix, real-device runs, and the [release checklist](release-checklist.md) reflect the supported developer experience | [#102](https://github.com/hewigovens/hw-core/issues/102), [#105](https://github.com/hewigovens/hw-core/issues/105), [#106](https://github.com/hewigovens/hw-core/issues/106), [#107](https://github.com/hewigovens/hw-core/issues/107), [#108](https://github.com/hewigovens/hw-core/issues/108) |

## Near-Term Priorities

1. Move THP transport and handshake onto `trezor-thp` and re-validate on real Safe 7 hardware ([#98](https://github.com/hewigovens/hw-core/issues/98), [#106](https://github.com/hewigovens/hw-core/issues/106)).
2. Close protocol gaps against Trezor Suite behavior for ETH, SOL, and BTC signing ([#99](https://github.com/hewigovens/hw-core/issues/99), [#100](https://github.com/hewigovens/hw-core/issues/100), [#101](https://github.com/hewigovens/hw-core/issues/101)).
3. Package Android and Apple outputs and document the consumer integration path ([#109](https://github.com/hewigovens/hw-core/issues/109), [#110](https://github.com/hewigovens/hw-core/issues/110), [#112](https://github.com/hewigovens/hw-core/issues/112)).
4. Keep validation narrow and explicit: CI and smoke checks cover only the flows we claim to support.

## Risks

- BLE reconnect behavior is sensitive to platform differences and pairing state; emulator coverage does not replace real-device runs.
- Packaging will expose API sharp edges currently hidden by in-repo sample apps.
- Firmware THP changes can drift from hw-core until the transport is built on `trezor-thp`.

## Non-Goals

- Transports beyond BLE, or new transport abstractions.
- Multi-vendor wallet support (the stack is designed to allow it later).
- Chain expansion beyond gaps that block current developer adoption.
- Sample-app UX polish that does not improve integration reliability.
- Large refactors that do not materially reduce consumer risk.
