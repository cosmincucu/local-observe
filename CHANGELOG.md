# Changelog

## Unreleased

Built-in scheduled investigations retain redacted evidence, bounded model/source work,
independent feedback and corrected-case retrieval. Guided setup produces a reviewable
plan and applies it through a separate trusted runner. Optional Telegram delivery
requires measured quality, human acceptance, its own daily budget and reconciliation
after restart or restore. Recording is the default.

Load-balanced model gateways can use a protected route declaration to retain bounded per-call
member receipts without changing routing. Unknown versions stay unknown; pooled quality acceptance
is explicitly unavailable. Existing single-deployment records and evaluation remain supported.

The evaluator compares the actual observer with deterministic baselines and preserves
unknown labels and incomplete coverage. Synthetic validation does not establish live
model quality, hardware fit or human review workload.

The inventory can be exported one way to a LogicMonitor portal with
`lo-inventory export-logicmonitor`. The command plans by default, adopts existing devices
only on unambiguous matches, never deletes a device, and needs `--apply` within a change
limit before it writes anything.

### Operator actions

- Route receipts are opt-in through `LO_OBSERVER_MODEL_ROUTES`; follow the protected declaration
  format in the [observer walkthrough](docs/units/observer.md). No journal migration is required.
  Keep older declarations with configuration backups to interpret historical digests.
- Optional platform settings: `LO_GUIDED_SETUP_ROOT`, `LO_GUIDED_SETUP_RUNNER` and
  `LO_TRUSTED_RUNNERS_FILE`; see [guided setup](docs/units/guided-setup.md). No settings
  are renamed or removed. Observer settings and optional provider/version labels are
  documented in the [walkthrough](docs/units/observer.md).
- Migrate existing platform state explicitly to schema 10 using
  `lo-platform --database /approved/private/platform.db migrate`, after a fresh verified
  backup and isolated rehearsal. See the [upgrade procedure](components/control/platform/upgrade.md).
  Observer journal schema 1 uses a separate owned private directory outside Git.
- Build and pin new first-party platform/MCP images from the accepted source revision.
  No published image or changed third-party image/compiler pin is supplied here.
- No rule recompilation or dashboard re-import is required by this change.
- Observer and runner services need explicit commands. Compose `command`, `entrypoint`
  and healthcheck `test` replace existing values; inspect the rendered configuration.
- Rollback requires the previous accepted image plus a compatible verified state,
  configuration and journal checkpoint. Keep dispatch off while reconciling external
  effects; an older backup must not silently re-arm actions or notifications.
