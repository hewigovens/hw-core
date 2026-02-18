# AGENTS.md

This file provides guidance to AI coding agents working in this repository.

## Source of Truth for Behavior

- When debugging protocol/flow mismatches, always check the Trezor Suite implementation first:
  - `~/workspace/github/trezor-suite`
- Treat Trezor Suite app behavior as the reference for:
  - request payload shapes
  - derivation path/account handling
  - signing request construction
  - user-facing pairing/connect/address/sign flows

## Existing Project Guidance

- The full repository guidance is maintained in `CLAUDE.md`.
- Read and follow `CLAUDE.md` for architecture, commands, conventions, and testing workflow.
