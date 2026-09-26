# Product and deployment repositories

The product repository holds reusable code, schemas, component manifests and
release metadata. Your deployment repository pins that product and versions
installation settings, content and overrides. Keep runtime data and secret values
in protected stores and backups, outside both content histories. An existing
infrastructure repository can be the deployment repository; there is no need for
a new repository per service.

Upgrade the pinned product and review the deployment changes together under the
[customisation contract](DEPLOYMENT.md) and [release contract](RELEASING.md).
Selecting this layout does not prove a deployment has migrated or an upgrade has
passed its checks. The established term `operator` in these documents names the
person or repository responsible for an installation; it is not a single-user
product limit.

## What each side holds

| Content | Product repository | Your deployment repository |
|---|---|---|
| Code, schemas, component manifests, image and lock pins, tests, generic examples | holds | pins |
| Overlays (host paths, ports, resource caps, extra mounts), `.env` values, dashboards, Sigma rules and compiled artifacts, DAGs, inventory declarations, migration baselines | example or nothing | holds, committed — never merely gitignored |
| Secret values, databases, telemetry, sessions | never | never in git; file-mounted at runtime, separately backed up |

Nothing here imports a deployment repository to start, and no generated render is
an authoring source. Anything one side gitignores needs one command that
regenerates it and one check that fails when it is missing or stale; without that
pair it is not a build artefact, it is the only copy.

Composing the two sides follows the merge rules in
[examples/full/compose.yaml](../examples/full/compose.yaml): one `include:` entry
per concern, and one entry listing the pinned manifest **and** your override
together with an explicit `project_directory` where they must merge as a single
service definition.

Release governance — who cuts a tag, the four promises a tag carries, the required
`Operator actions` block, and the two gates this product ships for your own CI
(`scripts/operator/pin_check.py` and `scripts/operator/overlay_gate.sh`) — is the
contract in [RELEASING.md](RELEASING.md).
