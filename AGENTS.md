# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## Project

hw-core is a Rust workspace for host-to-hardware crypto wallet communication. The first target is Trezor Safe 7 over BLE using the Trezor Host Protocol (THP). The transport/core stack is designed to be shared across wallet vendors.

## Skills

**All skills are mandatory reading** before making changes.

- [Project Overview](skills/project-overview.md) – Crate architecture, dependency graph, feature flags, and key design patterns
- [Development Commands](skills/development-commands.md) – Building, testing, linting, running the CLI, and generating bindings
- [Code Style](skills/code-style.md) – Module organization, async patterns, and trait design
- [Error Handling](skills/error-handling.md) – Layered `thiserror` enums, `Result` returns, and no panics in production
- [Defensive Programming](skills/defensive-programming.md) – Type safety, exhaustive matching, and safe defaults
- [Naming](skills/naming.md) – Rust naming conventions and project-specific terminology
- [Tests](skills/tests.md) – Test organization, MockBackend, proptest, and fixture patterns
- [Comments](skills/comments.md) – When and how to write comments and doc comments
- [Commit Guidelines](skills/commit-guidelines.md) – jj + sibling workspace workflow, Conventional Commits format, and PR checklist
- [Common Issues](skills/common-issues.md) – Known build, BLE, and platform-specific issues

## Version Control

- The repo is colocated jj + git. Use `jj` for most work (commits, rebases, bookmarks, pushes); never `git pull` or `git checkout` in the main checkout.
- Work in a sibling jj workspace per task: `jj workspace add ../hw-core-<topic> --name <topic> -r main@origin`.
- Details in [Commit Guidelines](skills/commit-guidelines.md).

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

## Comments and Docstrings

- Comments and docstrings are opt-in, not default.
- When needed, keep them to a single line.
- Prefer no comment unless it explains intent, invariants, or safety that the code cannot make obvious on its own.

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
- **Development status**: See [docs/roadmap.md](docs/roadmap.md) and [docs/plan.md](docs/plan.md)
