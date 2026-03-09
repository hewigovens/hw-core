# hw-core Roadmap

Last updated: 2026-03-09

## Product Goal
Ship a stable, reusable host stack for hardware-wallet communication over THP/BLE that external developers can adopt through well-defined Rust and FFI surfaces.

## Current Baseline
- THP/BLE host stack is operational end-to-end for discovery, pairing, session establishment, encrypted messaging, and persisted pairing state.
- Shared wallet orchestration (`hw-wallet`) is used by CLI and FFI.
- CLI supports scan, pair, address, sign-tx, and message-signing workflows.
- `hw-ffi` generates Swift/Kotlin bindings consumed by Apple and Android sample surfaces.

## Feature Status

| Capability | Ethereum | Bitcoin | Solana |
|---|---|---|---|
| Address retrieval | Done | Done | Done |
| Transaction signing | Done | Partial (advanced `TxRequest` variants pending) | Done |
| Message signing | Done (EIP-191 + EIP-712) | Done | Deferred |

## Near-Term Priorities
1. Complete protocol gaps and shared validation for supported ETH/BTC flows.
2. Make Android and Apple consumption paths supportable through packaged artifacts and integration docs.
3. Narrow validation and CI to the developer-facing flows we explicitly support.

## Milestones

| Milestone | Status | Exit Criteria |
|---|---|---|
| M1: Protocol-complete baseline | In progress | BTC signing handles the full supported firmware-requested `TX*` sequence and consumer-facing validation is shared across entry points |
| M2: Consumer-ready SDK surfaces | In progress | Android and Apple consumers can integrate hw-core from packaged artifacts using documented setup |
| M3: Release confidence | In progress | CI, smoke checks, and release docs reflect the actual supported developer experience |

## Not the Current Focus
- Expanding beyond the current transport model.
- Multi-vendor wallet support.
- Additional chain work beyond gaps that block current developer adoption.
- Sample-app UX polish that does not improve integration reliability.
