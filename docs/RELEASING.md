# Release contract

A release identifies immutable source, dependency pins and compatibility requirements. A tag
must resolve to one commit and must not move. Installations decide when to adopt it; a tag does
not authorize deployment or state changes.

## Release contents

- State and content schema versions, with explicit migration and restore requirements.
- The required Compose variables and example templates that declare them.
- Component image digests and dependency locks. Build first-party images from reviewed source
  and record their verified identities; the repository does not supply published images.
- The runtime compatibility declaration from `lo-deployment schema release`, including source
  pins, resolved images, API contracts, notification guard level and state compatibility.

Run automated checks and relevant component conformance. Record what was tested and what remains
unverified. Unit tests, an available image and a successful deployment are separate facts. Review
source, licenses, secrets, Git identities and history before publication.

## Operator actions

Every release entry in [CHANGELOG.md](CHANGELOG.md) must include a `### Operator actions` block:

1. Variables added, renamed and removed. Show both names for a rename.
2. State migration: whether required, source and target versions, and the exact command.
3. Image pin changes: component, previous identity and new identity.
4. Required rule recompiles and compiler pins.
5. Required dashboard re-imports.
6. Overlay keys replaced by Compose: `command`, `entrypoint` and `test` replace existing values.
7. Rollback: the previous release and verified backup needed to restore compatible state.

Write `Operator actions: none` when nothing is required. Restoring a previous image alone does
not reverse a state migration.

## Deployment checks

An installation can commit a `local-observe.pin.json` with exactly `tag`, `commit` and `images`:

```json
{"tag": "v0.1.0", "commit": "<40 hex>",
 "images": {"LO_SIGNOZ_IMAGE": "example/signoz@sha256:<64 hex>"}}
```

`scripts/operator/pin_check.py --pin <file> --checkout <product-checkout>` checks the tag, commit
and recorded image digests. Unknown keys, floating images and mismatched pins are refused.

`scripts/operator/overlay_gate.sh --root <checkout> --pin <file> <model>...` also runs foundation
checks over merged Compose models. Includes must resolve inside the product checkout or the
supplied model's directory. Credential, notification and collector checks still apply. Collector
checks identify shipped service names; renaming a service requires independent review.

These checks compare files. Use `lo-deployment verify-release` and component conformance to
verify a running installation. Keep private configuration and acceptance receipts in the deployment
repository or protected storage described by [DEPLOYMENT.md](DEPLOYMENT.md).
