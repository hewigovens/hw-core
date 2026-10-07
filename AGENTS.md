# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## Project

hw-core is a Rust workspace for host-to-hardware crypto wallet communication. The first target is Trezor Safe 7 over BLE using the Trezor Host Protocol (THP). The transport/core stack is designed to be shared across wallet vendors.

## Agent Docs

Read this file first, then load the focused guides needed for the task. Repository constraints live here; detailed rules have one owning guide.

| Task | Read |
| --- | --- |
| Crate boundaries, shared behavior, or FFI ownership | [Project Overview](agents/project-overview.md) |
| Build, lint, bindings, or running sample apps | [Development Commands](agents/development-commands.md) |
| Rust implementation | [Code Style](agents/code-style.md), [Error Handling](agents/error-handling.md), [Defensive Programming](agents/defensive-programming.md), [Comments](agents/comments.md) |
| New types or APIs | [Naming](agents/naming.md) |
| Tests, fixtures, or validation | [Tests](agents/tests.md) |
| Reviewing a patch | [Code Review](agents/code-review.md) and the guides for the changed area |
| JJ history, workspaces, or PRs | [Commit Guidelines](agents/commit-guidelines.md) |
| Build, BLE, or platform troubleshooting | [Common Issues](agents/common-issues.md) |

## Task Scope

- Investigation and code review are read-only unless implementation is requested. Report concrete findings and the smallest viable fix.
- Keep implementation within the requested behavior; preserve unrelated work and report unrelated defects separately.
- Keep changes local unless publication is requested. A request to implement does not authorize pushing, opening or merging PRs, or posting external comments.
- Report build, focused tests, binding generation, emulator, physical-device, and platform checks separately. State what ran and what was skipped or blocked; success in one layer does not prove another.

## Version Control

- The repo is colocated jj + git. Use `jj` for most work (commits, rebases, bookmarks, pushes); never `git pull` or `git checkout` in the main checkout.
- Work in a sibling jj workspace per task: `jj workspace add ../hw-core-<topic> --name <topic> -r main@origin`.
- Details in [Commit Guidelines](agents/commit-guidelines.md).

## Formatting (mandatory)

After any code changes, run formatting before finishing:

```bash
just fmt && just lint
```

Or explicitly:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

For documentation-only changes, check the diff, local links, and command references; application builds, formatting, and lint are unnecessary unless executable behavior also changes. See [Tests](agents/tests.md) for focused validation and [Commit Guidelines](agents/commit-guidelines.md) for PR gates.

## Source of Truth for Behavior

- When debugging protocol/flow mismatches, always check the Trezor Suite implementation first: `~/workspace/github/trezor-suite`
- Treat Trezor Suite app behavior as the reference for:
  - request payload shapes
  - derivation path/account handling
  - signing request construction
  - user-facing pairing/connect/address/sign flows
- Fetch/update `~/workspace/github/trezor-suite` (and `~/workspace/github/trezor-firmware`) before comparing; local checkouts go stale.
- Suite's connect logic lives in `packages/connect-core` (formerly `packages/connect`); the THP transport loop is in `packages/transport-common/src/thp`.
- Firmware THP implementation is in `rust/trezor-thp`; the spec is `docs/common/thp/specification.md`.

## Other Notes

- **Build times**: Initial build takes several minutes; incremental builds are fast with sccache
- **Linux BLE**: Requires `sudo apt-get install -y libdbus-1-dev pkg-config`
- **Pairing state**: Stored at `~/.hw-core/thp-host.json`; use `pair --force` to reset
- **License**: Apache-2.0
- **Development status**: See [docs/roadmap.md](docs/roadmap.md) and [GitHub issues](https://github.com/hewigovens/hw-core/issues)
