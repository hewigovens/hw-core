# hw-core Release Checklist

Last updated: 2026-03-10

Use this checklist before cutting a tagged release or publishing downstream artifacts.

## Code Health

- [ ] `just ci` passes on the release commit.
- [ ] Open plan items that block the stated release scope are resolved or explicitly deferred.
- [ ] `docs/plan.md` and `docs/roadmap.md` reflect the same release priorities.

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

## Sign-Off

- [ ] Release artifacts were verified from a clean checkout or CI-produced output.
- [ ] Known limitations are documented in the release notes.
- [ ] The final tag/commit SHA used for artifacts is recorded.
