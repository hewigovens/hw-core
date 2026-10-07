# Commit Guidelines

For code changes, run `just ci` locally before opening a PR. Documentation-only changes use the [documentation validation policy](../AGENTS.md#formatting-mandatory).

## Version Control: jj + Sibling Workspaces

The repo is a colocated [jj](https://jj-vcs.github.io/jj/) + git repo. Use `jj` for most work: commits, rebases, bookmarks (branches) and pushes. Read-only git commands (`git log`, `git diff`, `git show`) are fine. Do not `git pull`, `git checkout` or `git worktree add` in the main checkout; git's HEAD is detached and managed by jj.

Do each task in its own sibling workspace instead of the main checkout:

```bash
jj git fetch
jj workspace add ../hw-core-<topic> --name <topic> -r main@origin
cd ../hw-core-<topic>
```

Day-to-day:

```bash
jj commit -m "fix(connect): ..."           # describe @ and start a new empty change
jj squash --into <change-id>                # fold the working copy into an earlier change
jj git fetch && jj rebase -d main@origin    # catch up with main
jj git push --named <branch>=@-             # first push of a new branch
jj bookmark set <branch> -r @- && jj git push -b <branch>   # later pushes
```

Secondary workspaces have no `.git`, so pass the repo to `gh`:
`gh pr create --repo hewigovens/hw-core --head <branch>`.

Keep work awaiting review in its registered workspace. After the PR merges, verify the workspace contains no unlanded work before forgetting it with `jj workspace forget <topic>` and removing its directory and local bookmark.

## JJ Concurrency and Build Isolation

- Serialize JJ commands within each workspace, including reads that can snapshot the working copy. Parallel JJ work belongs in separate workspaces.
- Use `jj --ignore-working-copy log`, `jj --ignore-working-copy diff --from <base> --to <head>`, and `jj --ignore-working-copy workspace list` for history-only reads. Omit the flag when inspecting or recording current file edits.
- After history changes or concurrent workspace work, check `jj --ignore-working-copy log -r 'divergent()' --no-graph`; preserve unrelated divergence and compare immutable commits before resolving versions created by this task.
- Keep scratch logs and fixtures outside the workspace unless intentionally part of the change.
- Keep each workspace's own Cargo `target/` for concurrent builds; do not share `CARGO_TARGET_DIR`. Preserve the configured compiler cache rather than changing global settings.

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]
```

### Types

- `feat` — new feature
- `fix` — bug fix
- `refactor` — code change that neither fixes a bug nor adds a feature
- `test` — adding or updating tests
- `docs` — documentation changes
- `chore` — build, CI, dependency updates
- `perf` — performance improvement

### Scopes

Use the crate name without prefix: `proto`, `ble`, `connect`, `wallet`, `ffi`, `cli`, `chain`.

```
feat(connect): add Solana signing support
fix(ble): handle transport timeout on Android
refactor(wallet): extract session retry logic
test(connect): add vectors for continuation frames
chore(ci): add cargo fmt check step
```

## Commit Best Practices

- **One logical change per commit.** Do not mix refactoring with feature work.
- **Write clear, concise commit messages.** The subject line should be under 72 characters.
- **Do not commit generated code.** Proto-generated files, UniFFI bindings, and build artifacts belong in `.gitignore`.

## Pull Requests

- Keep PRs focused on a single concern.
- Add or update tests for behavior changes.
- Update docs when public behavior or workflow changes.
- Reference related issues in the PR description.
