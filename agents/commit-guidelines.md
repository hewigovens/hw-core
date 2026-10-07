# Commit Guidelines

**IMPORTANT**: Always run `just ci` locally before opening a PR.

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

After the PR merges: `jj workspace forget <topic>`, remove `../hw-core-<topic>`, and `jj bookmark delete <branch>`.

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
