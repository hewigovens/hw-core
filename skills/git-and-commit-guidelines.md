# Git and Commit Guidelines

**IMPORTANT**: Always run `just ci` locally before opening a PR.

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

Use the crate name without prefix: `codec`, `crypto`, `core`, `proto`, `ble`, `connect`, `wallet`, `ffi`, `cli`, `chain`.

```
feat(connect): add Solana signing support
fix(ble): handle transport timeout on Android
refactor(wallet): extract session retry logic
test(codec): add proptest for continuation frames
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
