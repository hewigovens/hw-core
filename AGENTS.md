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
- [Git and Commit Guidelines](skills/git-and-commit-guidelines.md) – Conventional Commits format and PR checklist
- [Common Issues](skills/common-issues.md) – Known build, BLE, and platform-specific issues

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

## Source of Truth for Behavior

- When debugging protocol/flow mismatches, always check the Trezor Suite implementation first: `~/workspace/github/trezor-suite`
- Treat Trezor Suite app behavior as the reference for:
  - request payload shapes
  - derivation path/account handling
  - signing request construction
  - user-facing pairing/connect/address/sign flows

## Other Notes

- **Build times**: Initial build takes several minutes; incremental builds are fast with sccache
- **Linux BLE**: Requires `sudo apt-get install -y libdbus-1-dev pkg-config`
- **Pairing state**: Stored at `~/.hw-core/thp-host.json`; use `pair --force` to reset
- **License**: GPL-3.0-only
- **Development status**: See [docs/roadmap.md](docs/roadmap.md) and [docs/plan.md](docs/plan.md)
