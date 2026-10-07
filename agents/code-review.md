# Code Review

Load this guide when reviewing local changes or pull requests. Follow [task scope](../AGENTS.md#task-scope) and the focused guides for the changed area.

## Establish the Target

- Pin the workspace, base, and head before reviewing; use immutable commit IDs when JJ change IDs have multiple versions.
- Read the full changed files and their callers. Compare against the base to separate introduced defects from pre-existing behavior.
- For a live PR, verify checks against the reviewed head; if it moves, refresh affected evidence or state that it is stale.
- Check generated protobuf or binding changes against their source inputs; do not repair generated output directly.

## Challenge the Behavior

- Infer the contract from the task, public API, callers, and protocol reference. For protocol or flow mismatches, follow the [Trezor reference policy](../AGENTS.md#source-of-truth-for-behavior) and record the Suite/firmware revisions used.
- Construct reachable counterexamples to the changed assumptions: malformed or truncated frames, numeric limits, repeated requests, cancellation, disconnects, stale sessions, retry exhaustion, and partial persistence failures where relevant.
- Trace checks across await points: an old connection or session must not apply its completion to replacement state. Check cleanup, error propagation, and whether a retry can repeat an operation whose outcome is unknown.
- Trace request construction through derivation paths, account selection, and signing payloads when affected. Check actual callers and guards before claiming a failure.
- Follow the affected path through transport, THP workflow, wallet orchestration, CLI or FFI, and platform consumers. Prefer a fix at the shared owner; inspect sibling entry points for the same assumption.
- For changed trust boundaries, inspect authentication failures, secret exposure in logs/errors, and persisted credentials. Keep this scoped to the patch.

## Validate and Report

- Use the smallest reproducer or test that proves the failure. Follow [Tests](tests.md); a regression should fail on the pre-fix code for the intended reason.
- Report concrete defects first, ordered by severity, with file/line, trigger, expected versus actual behavior, impact, and a minimal fix. State whether the failure was reproduced or established by code tracing.
- List verification gaps and pre-existing defects separately. Missing coverage or a style preference alone is not a demonstrated defect.
- If no defects are found, say so and identify any remaining verification limits.
- After requested fixes, re-check the full patch for unresolved defects and regressions. Stop when the requested contract holds and affected checks pass; do not expand the feature during review.
