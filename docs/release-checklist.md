# hw-core Release Checklist

Last updated: 2026-10-07

Use this checklist before cutting a tagged release or publishing downstream artifacts.

## Code Health

- [ ] `just ci` passes on the release commit.
- [ ] Open GitHub issues that block the stated release scope are resolved or explicitly deferred.
- [ ] `docs/roadmap.md` reflects the release priorities.

## Bindings And Artifacts

- [ ] `just bindings` completes successfully.
- [ ] Apple Swift bindings are synced into `apple/HWCoreKit`.
- [ ] Android bindings are synced into `android/lib`.
- [ ] Required Apple artifact output is built for the target release scope.
- [ ] Required Android artifact output is built for the target release scope.

## Smoke Validation

- [ ] CLI smoke flows in `docs/smoke-matrix.md` are green for the supported release platform.
- [ ] Apple smoke flows in `docs/smoke-matrix.md` are green for the supported release platform.
- [ ] Android smoke flows in `docs/smoke-matrix.md` are green for the supported release platform.
- [ ] Any required real-device BLE pairing/reconnect checks were run and recorded.

## Docs And Packaging

- [ ] `README.md` matches the shipped command surface and artifact story.
- [ ] `CONTRIBUTING.md` still matches the supported developer workflow.
- [ ] Apple integration docs match the published package/output.
- [ ] Android integration docs match the published package/output.
- [ ] Version numbers and release notes are updated where required.

## Crates.io

The root manifest is a virtual workspace, so the published packages are
`ble-transport`, `hw-chain`, `thp-proto`, `trezor-connect`, `hw-wallet`, `hw-cli`,
and `hw-ffi`. There is no package named `hw-core`.

- [ ] The crates.io account has a verified email and permission to publish each package.
- [ ] For an initial publication, a local Cargo API token permits creating the new crates.
- [ ] Every archive includes its README, license text, and required build inputs, including the vendored THP protobuf files.
- [ ] The release lockfile contains no yanked dependencies.
- [ ] Package verification passes on the exact release commit:

```bash
cargo package --workspace --list --locked
cargo publish --workspace --dry-run --locked
```

After validation, publish with Cargo's workspace support, which orders packages
by their dependencies:

```bash
cargo publish --workspace --locked
```

For later releases, configure [crates.io Trusted Publishing](https://crates.io/docs/trusted-publishing)
for each package and add a GitHub Actions publishing workflow. The first version
of each crate must be published with an API token before configuring a trusted publisher.

Publishing Rust crate sources does not distribute Swift or Kotlin packages;
validate and release those artifacts separately when they are in scope.

## Sign-Off

- [ ] Release artifacts were verified from a clean checkout or CI-produced output.
- [ ] Known limitations are documented in the release notes.
- [ ] The final tag/commit SHA used for artifacts is recorded.
