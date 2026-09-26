# Product, deployments and customisations

local-observe provides reusable telemetry and operational workflows for your installation.
The public product repository is the source of truth. Installations consume pinned
releases and maintain their own configuration and protected runtime state.

## Two histories, one deployment

The product repository owns code, schemas, generic defaults, supported adapters,
tests, migration tools and release metadata. The operator owns a separate Git
history containing deployment choices, environment bindings, custom tiles,
dashboards, rules and selected content packages. An existing infrastructure
repository can hold these inputs; a dedicated private repository uses the same interface.
Separate ownership does not require creating a new repository for every service.

Deploy a reviewed product release together with a reviewed customisation commit
and exact package pins. Pulling new product code must not replace operator
content. Generated configuration is disposable output, not another authoring
source. Databases, telemetry, sessions and secret values belong in separately
protected runtime stores and backups, not either content history.

Every installation follows the same contract. Product startup must
not import a private deployment repository or require its domains, machines,
personal assistant, secrets provider or forge.
Private adapters stay downstream unless they become genuinely generic, tested
interfaces suitable for the product.

## Customisation without a permanent fork

Prefer user-owned additions, explicit settings and versioned data packages.
Use permanent logical IDs independent of titles, URLs and backend UUIDs. Edit a
product default through a hash-pinned override, or make an independent user-owned
copy. Upstream changes beneath an override require review; there is no guessed
deep merge of nested JSON, arrays or dashboards.

Dashboard UI edits are useful authoring drafts. Export them from the live backend,
review the native query/panel definitions and commit the chosen result downstream.
Unreviewed runtime drift blocks upgrades. Do not silently overwrite it or silently
adopt it as the new baseline. Backup/restore of runtime state is a different
operation from exporting content into Git.

Executable plugins and arbitrary install hooks are not supported by the v1 data
contract. A future plugin system needs independent API/version compatibility,
permissions, isolation, provenance and lifecycle rules. A repository directory
called `plugins` must not become an implicit code-execution mechanism.

## Required, optional and external

The selected foundation provides telemetry ingestion and query through OpenTelemetry
and SigNoz/ClickHouse. Optional capabilities declare dependencies, resource cost,
credentials and acceptance checks. Installing the core must not require AI, a chat
bot, local model serving or every supported sensor. An explicitly selected module
may require another capability; that dependency must be visible before deployment.

An integration is not ownership of the integrated service. DNS, Gitea, Jellyfin,
qBittorrent, Home Assistant and similar services remain independently operated.
A Homepage tile is navigation; a widget is a data dependency; a collector ingests
telemetry; an action adapter can change something. These are distinct permissions
and failure modes, not a single blanket integration grant.

Existing DNS, access gateways, secrets stores, schedulers and notification
providers may fulfil contracts instead of bundled alternatives. Keep native
third-party interfaces available. Treat an unavailable optional integration as
unavailable, not healthy; do not make unrelated core operations depend on it.
A private assistant or Telegram binding is an optional delivery choice, not a required
product account or a replacement for other notification adapters.

## Documentation vocabulary

The words and the release curation rule live in [the voice contract](VOICE.md): address the reader
as **you** and their system as **the deployment**, name **the project maintainer** for release
responsibility, say **a person** or **a manually approved action** in prose, and leave shipped
literals — the `human` authorization role, `lo-operator-setup`, the `Operator actions` block, API
fields and stored values — to a migration with its own decision.

## Upgrades are reviewed operations

1. Select immutable product source, images and content packages. Resolve against
   the customisation commit and verify compatibility with selected capabilities.
2. Export current managed content from running services. Check completeness,
   identity mappings, freshness, drift, removals and unmanaged collisions.
3. Check state/schema compatibility; take consistent backups and demonstrate
   restore. Quiesce writers where an API cannot support conditional updates.
4. Recheck immediately before applying into a new deployment directory. Test
   actual running services, private content, integrations and persisted state.
5. Advance the last-applied receipt only after acceptance. On failure, retain the
   last accepted receipt and restore the compatible application and state.

A digest establishes integrity against a reviewed pin, not publisher trust.
Development snapshots must be labelled honestly; a dirty checkout is not the
commit at HEAD. Database downgrade is not promised by switching an image tag.
Unknown state versions fail closed until an explicit migration/restore path exists.

## Current implementation boundary

The supported installation experience is not a suite of hand-ordered staging
scripts. The core should have one versioned deployment entrypoint; selected host
integrations need explicit, packaged enrollment and lifecycle support. Runbooks
explain recovery and exceptions, not missing install automation. This remains
Validate installation and lifecycle behavior using the selected component contracts.

See [the deployment contract](DEPLOYMENT.md), [migration plan](MIGRATION.md) and
[STATUS](../STATUS.md) for implemented and rehearsed scope. This philosophy is
the architectural direction, not a claim that a public release manager, arbitrary
plugin installation or every external integration is already delivered.
