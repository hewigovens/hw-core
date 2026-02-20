# hw-core Roadmap

Last updated: 2026-02-20

## Product Goal
Ship a stable, reusable host stack for hardware-wallet communication over THP/BLE, with consistent behavior across CLI and mobile/desktop app surfaces.

## Current Baseline
- THP/BLE host stack is operational end-to-end (discovery, pairing, session, encrypted messaging, persistence).
- Shared wallet orchestration (`hw-wallet`) is used by CLI and FFI.
- CLI supports scan/pair/address/sign and message-signing workflows.
- `hw-ffi` bindings are generated for Swift/Kotlin and consumed by Apple app surfaces.
- Apple sample app supports scan/pair/connect/address/sign flows with UI smoke coverage (`just test-mac-ui`, `just test-ios-ui`).

## Feature Status

| Capability | Ethereum | Bitcoin | Solana |
|---|---|---|---|
| Address retrieval | Done | Done | Done |
| Transaction signing | Done | Partial (advanced `TxRequest` variants pending) | Done |
| Message signing | Done (EIP-191 + EIP-712) | Done | Deferred |

## Near-Term Priorities
1. Complete advanced Bitcoin signing request support (`TXORIGINPUT`, `TXORIGOUTPUT`, `TXPAYMENTREQ`).
2. Deliver a runnable Android sample app wired to generated Kotlin bindings.
3. Expand integration and UI validation coverage, then wire required checks into CI.
4. Refactor and simplify core modules to reduce duplication and improve maintainability.
5. Keep docs focused and synchronized with implemented behavior.

## Milestones

| Milestone | Status | Exit Criteria |
|---|---|---|
| M1: Core protocol parity | In progress | BTC signing handles full firmware-requested `TX*` sequence without "not implemented" errors |
| M2: Cross-surface parity | In progress | CLI + Apple + Android sample cover scan/pair/connect/address/sign happy path |
| M3: Reliability and validation | In progress | Deterministic retry/recovery behavior and documented smoke checks across surfaces |
| M4: CI and release readiness | Planned | CI validates build/test/bindings/sample-app health and docs match shipped behavior |
| M5: Code health and simplification | In progress | Shared logic is consolidated, modules are easier to reason about, and refactors are regression-tested |

## Long-Term Direction
- Additional transport abstractions beyond BLE.
- Multi-vendor wallet profile support.
- Broader chaos/reconnect test matrix for production readiness.
