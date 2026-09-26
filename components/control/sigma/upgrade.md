# Upgrade

Pin the compiler interpreter, compiler.lock and build inputs. Regenerate compiled
artifacts in CI and compare positive/negative/boundary/NULL fixtures against the
actual reference-store schema before promotion. No compiler runs in the service.

Drain the old pending batch, back up cursor/platform state and preserve old
artifacts. Deploy a candidate with a fresh version-bound cursor and disabled
outbound delivery, verify event/incident expectations, then enable it deliberately.
Rollback uses the old artifact/cursor; reconcile events already accepted from the
candidate rather than deleting operational history. No forward schema migration
or upgrade compatibility beyond the tested state v1 is claimed.
