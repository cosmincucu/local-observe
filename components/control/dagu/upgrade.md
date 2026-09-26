# Upgrade

Drain claims, back up state and preserve the exact old image/DAG/binding/journals.
Boot the candidate on copied engine data, a separate network and different loopback
port. Verify authentication, actual API envelope, known-run history, one new
synthetic approved run and lost-response reconciliation. Promote only after
those checks, retaining the old deployment and verified backup for rollback.

Do not substitute an old engine against migrated live data. Roll back the engine
and its copied pre-upgrade data together, then reconcile external effects with
platform state. No engine-version upgrade rehearsal has passed yet.
