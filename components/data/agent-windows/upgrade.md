# Upgrade

Retain the old executable/config/state and verify a fresh backup before upgrade.
Validate the candidate config, then run the native synthetic conformance with
copied state and a separate receiver. Require per-CPU labels, exact marker count,
queue restart and resource UUID checks. Restore the old binary plus pre-upgrade
state on rollback, not an older binary against unverified migrated state.

## Moving the pin

`versions.json` is the pin, so an upgrade is a commit that changes it and nothing else: new
`collector.version`, the new release `asset`/`url`/`publisher_checksum_url`, a freshly downloaded
archive's `archive_sha256` and the *extracted* `binary_sha256`, each produced by the
[provenance recipe](CONTRACT.md#provenance-download-verify-then-install) rather than copied from a
changelog, with `publisher_checksum_verified` set from what the recipe actually observed.
`scripts/check_windows_agent.py` compares the on-disk executable against `binary_sha256` and the
binary's own `--version` against `version`, so a half-moved pin (new prose, old hash, or the
reverse) stops the check instead of drifting quietly. Nothing infrastructure-grade upgrades itself:
the change is seen running against its real consumers before it merges, and the merge authorises
promotion rather than closing the item.

**0.159.0 → 0.160.0 is deliberately not done here.** Upstream current is v0.160.0 (2026-09-02); the
remediation ledger records that move as *pending-data-pass* and this component is one contrib version
with the front door and the store collector, so it moves on its own branch with a reason and a
rollback line, in all three places at once.

## Rehearsal state

An isolated 0.159.0 process was tested; **no native binary upgrade has been executed — not run.**
Neither has a rollback of a Windows host from a new executable to the retained old one, nor an
upgrade of the *service* in `CONTRACT.md` (which has never been installed by this product). Until
someone runs them here, `upgrade.md` is a procedure and `conformance.md` is the evidence, and the
difference is the point of writing them separately.

What an upgrade must not silently change: the three `resource/identity` attributes, the
`${file:C:/local-observe/agent/secrets/ingest-token}` credential path and its no-trailing-newline
rule, `service.telemetry.metrics.level: none` (an internal metrics reader binds `127.0.0.1:8888`
and collides with an already-installed agent — observed again 2026-09-08), and the option set of
`collector-security.yaml`, which is pinned to what v0.159.0 documents; re-read the
`windows_event_log` receiver's README at the new tag before carrying those fields forward, including whether
`channel` and `query` are still mutually exclusive.
