# hw-core

[![CI](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml/badge.svg)](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml)
[![Cargo Audit](https://github.com/hewigovens/hw-core/actions/workflows/audit.yml/badge.svg)](https://github.com/hewigovens/hw-core/actions/workflows/audit.yml)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue)](SECURITY.md)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](#license)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-orange)](https://www.rust-lang.org/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hewigovens/hw-core)

![hw-core banner](docs/banner.jpg)

`hw-core` is an early-stage Rust project building a cross-platform hardware wallet interface.

The first production target is THP (Trezor Host Protocol), introduced by Trezor Safe 7. The stack is designed so the same core workflow/orchestration can be reused across multiple app surfaces (the CLI, plus SwiftUI iOS/macOS and Android sample apps via FFI in `apple/` and `android/`).

High-level references:

- THP spec: [trezor-firmware/docs/common/thp/specification.md](https://github.com/trezor/trezor-firmware/blob/main/docs/common/thp/specification.md)
- Development and contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Architecture

```mermaid
%%{init: {'theme':'base', 'flowchart': {'rankSpacing': 45, 'nodeSpacing': 25, 'curve': 'basis'}}}%%
flowchart TB
  subgraph L1["Application Layer"]
    direction LR
    CLI["hw-cli"]
    APP["Apple / Android apps"]
  end

  subgraph L2["FFI Layer"]
    direction LR
    FFI_PAD[" "]
    FFI["hw-ffi (UniFFI)"]
    FFI_PAD --- FFI
  end

  subgraph L3["Wallet Layer"]
    direction TB
    WALLET["hw-wallet (shared orchestration)"]
    CHAIN["hw-chain (chain config)"]
    WALLET --> CHAIN
  end

  subgraph L4["Protocol Layer"]
    direction LR
    PROTO_PAD[" "]
    subgraph L4S[" "]
      direction TB
      CONNECT["trezor-connect (THP workflow/backend)"]
      THP["thp-core / thp-crypto / thp-proto"]
      BLE["ble-transport (BLE link)"]
      CONNECT --> THP
      THP --> BLE
    end
    PROTO_PAD --- CONNECT
  end

  subgraph L5["Hardware Layer"]
    direction LR
    HW_PAD[" "]
    DEVICE["Trezor Safe 7"]
    HW_PAD --- DEVICE
  end

  CLI --> WALLET
  APP --> FFI_PAD
  FFI --> WALLET
  CHAIN --> PROTO_PAD
  BLE --> HW_PAD

  classDef appLayer fill:#E3F2FD,stroke:#1E88E5,color:#0D47A1,stroke-width:1.5px;
  classDef ffiLayer fill:#E8F5E9,stroke:#43A047,color:#1B5E20,stroke-width:1.5px;
  classDef walletLayer fill:#FFF8E1,stroke:#FB8C00,color:#E65100,stroke-width:1.5px;
  classDef protoLayer fill:#ECEFF1,stroke:#546E7A,color:#263238,stroke-width:1.5px;
  classDef hwLayer fill:#FFEBEE,stroke:#E53935,color:#B71C1C,stroke-width:1.5px;
  classDef spacer fill:transparent,stroke:transparent,color:transparent;

  class CLI,APP appLayer;
  class FFI ffiLayer;
  class WALLET,CHAIN walletLayer;
  class CONNECT,BLE,THP protoLayer;
  class DEVICE hwLayer;
  class FFI_PAD,PROTO_PAD,HW_PAD spacer;
```

## Status

| Capability | Ethereum | Bitcoin | Solana |
|---|---|---|---|
| Address retrieval | Done | Done | Done |
| Transaction signing | Done | Partial | Done |
| Message signing | EIP-191, EIP-712 | Done | Not yet |

Transport is BLE only (Trezor Safe 7). Supported hosts: macOS and Linux (CLI), iOS/macOS via [HWCoreKit](apple/HWCoreKit/README.md), and Android via the [Kotlin library](android/README.md). See [docs/roadmap.md](docs/roadmap.md) for details.

## Quick start

```bash
cargo run -p hw-cli -- scan
cargo run -p hw-cli -- pair            # --force to re-pair
cargo run -p hw-cli -- address --chain eth
cargo run -p hw-cli -- sign-message eth --message "hello"
```

Pairing state is stored at `~/.hw-core/thp-host.json`. Add `-vv` for protocol logs. `just --list` shows the build, test and sample-app recipes; see [CONTRIBUTING.md](CONTRIBUTING.md) for setup, bindings, and the T3W1 emulator integration tests.

## Workspace layout

- `crates/hw-cli`: interactive CLI commands (`scan`, `pair`, `address`, `sign`, `sign-message`)
- `crates/hw-ffi`: UniFFI-compatible Rust surface for mobile/desktop apps
- `crates/hw-wallet`: shared wallet logic used by CLI + FFI
- `crates/hw-chain`: `Chain` enum and `ChainConfig` (code, SLIP-44 coin type, default BIP32 path)
- `crates/trezor-connect`: host-facing THP workflow + backend bridge
- `crates/ble-transport`: BLE manager and profile-specific transport behavior
- `crates/thp-*`: protocol primitives (crypto + wire framing, state machine, protobuf types)

## Roadmap

Current and planned milestones are tracked in:

- [docs/roadmap.md](docs/roadmap.md)
- [docs/plan.md](docs/plan.md)

## License

`hw-core` is licensed under the **Apache License 2.0** ([LICENSE](LICENSE)).
