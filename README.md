# hw-core

[![CI](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml/badge.svg)](https://github.com/hewigovens/hw-core/actions/workflows/ci.yml)
[![Cargo Audit](https://github.com/hewigovens/hw-core/actions/workflows/audit.yml/badge.svg)](https://github.com/hewigovens/hw-core/actions/workflows/audit.yml)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue)](SECURITY.md)
[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](#license)
[![Rust Edition](https://img.shields.io/badge/Rust-2024-orange)](https://www.rust-lang.org/)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/hewigovens/hw-core)

![hw-core banner](docs/banner.jpg)

`hw-core` is an early-stage Rust project building a cross-platform hardware wallet interface.

The first production target is THP (Trezor Host Protocol), introduced by Trezor Safe 7. The stack is designed so the same core workflow/orchestration can be reused across multiple app surfaces (CLI now, SwiftUI iOS/macOS via FFI next).

High-level references:

- THP spec: [trezor-firmware/docs/common/communication/thp.md](https://github.com/trezor/trezor-firmware/blob/m1nd3r/thp-documentation/docs/common/communication/thp.md)
- Development and contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Architecture

```mermaid
%%{init: {'theme':'base', 'flowchart': {'rankSpacing': 80, 'nodeSpacing': 55, 'curve': 'basis'}}}%%
flowchart TB
  subgraph L1["Application Layer"]
    CLI["hw-cli"]
    APP["SwiftUI app (iOS/macOS)"]
  end

  subgraph L2["FFI Layer"]
    FFI["hw-ffi (UniFFI)"]
  end

  subgraph L3["Wallet Layer"]
    WALLET["hw-wallet (shared orchestration)"]
    CHAIN["hw-chain (chain config)"]
  end

  subgraph L4["Protocol Layer"]
    CONNECT["trezor-connect (THP workflow/backend)"]
    BLE["ble-transport"]
    THP["thp-core / thp-crypto / thp-codec / thp-proto"]
  end

  subgraph L5["Hardware Layer"]
    DEVICE["Trezor Safe 7"]
  end

  CLI --> WALLET
  APP --> FFI
  FFI --> WALLET
  WALLET --> CHAIN
  WALLET --> CONNECT
  CONNECT --> BLE
  CONNECT --> THP
  BLE --> DEVICE

  classDef appLayer fill:#E3F2FD,stroke:#1E88E5,color:#0D47A1,stroke-width:1.5px;
  classDef ffiLayer fill:#E8F5E9,stroke:#43A047,color:#1B5E20,stroke-width:1.5px;
  classDef walletLayer fill:#FFF8E1,stroke:#FB8C00,color:#E65100,stroke-width:1.5px;
  classDef protoLayer fill:#ECEFF1,stroke:#546E7A,color:#263238,stroke-width:1.5px;
  classDef hwLayer fill:#FFEBEE,stroke:#E53935,color:#B71C1C,stroke-width:1.5px;

  class CLI,APP appLayer;
  class FFI ffiLayer;
  class WALLET,CHAIN walletLayer;
  class CONNECT,BLE,THP protoLayer;
  class DEVICE hwLayer;
```

## Workspace layout

- `crates/hw-cli`: interactive CLI commands (`scan`, `pair`, `address`, `sign`)
- `crates/hw-ffi`: UniFFI-compatible Rust surface for mobile/desktop apps
- `crates/hw-wallet`: shared wallet logic used by CLI + FFI
- `crates/hw-chain`: chain-level config and helpers (paths, SLIP-44, etc.)
- `crates/trezor-connect`: host-facing THP workflow + backend bridge
- `crates/ble-transport`: BLE manager and profile-specific transport behavior
- `crates/thp-*`: protocol primitives (codec, crypto, state machine, protobuf types)

## Roadmap

Current and planned milestones are tracked in:

- [docs/roadmap.md](docs/roadmap.md)
- [docs/plan.md](docs/plan.md)

## License

`hw-core` is licensed under **GNU General Public License v3.0 only (GPL-3.0-only)**.
