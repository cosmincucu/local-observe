"""Reusable CI failure ingestion: a bounded poller, its durable state, and a separately scoped board outlet.

This package reads completed/queued CI runs from a Gitea-compatible Actions API, folds them into
durable card identities, and files or updates **one** board issue per recurring failure signature.
It owns ingestion state (cursor, occurrence window, delivery journal, heartbeat) and nothing else:
incident state, notification decisions and severity vocabulary belong to `local_observe/platform/`
(`platform/state.py`, `platform/intake.py`), and this package hands those layers canonical events
through `adapter.py` instead of keeping a parallel incident table.

Two boundaries are structural rather than conventional, and each is pinned by a test:

* **Read scope.** `transports.ActionsSource` issues `GET` and nothing else, over four allowlisted
  Actions paths built from a validated `owner/name` repository identity. It cannot address an issue
  path at all, so no caller can widen the Actions reader into a writer.
* **Write scope.** `transports.BoardClient` is a second client with a second credential, holding the
  issue/label reads and the issue/comment writes the outlet needs. The two clients must be handed
  different transports (`pipeline.Pipeline` refuses one transport in two scopes).

Both outlets are optional. `platform_client.PlatformIntake` is the third, independent outlet: the host's
half of `adapter.PlatformAdmission`, posting canonical events to the platform's own intake routes so a
failing build becomes an incident there. A process with no board and a platform configured files nothing
anywhere and is the shape this package is meant to run in.

Every remote failure lands in one of three classes, and the class decides what happens to state:
a `ScopeRefused` is a bug or an attack and is never retried; a `MalformedSource` refuses the one
payload that carried it (loudly, durably, and past it — never a silent skip and never a poison pill
that freezes the cursor); a `SourceUnavailable` is an outage, which becomes *coverage* about this
ingestion source and leaves the cursor, the pending deliveries and the facts already recorded
untouched. Nothing here invents a diagnosis for data it did not read.

"""
from .transports import (ActionsSource, BoardClient, CiFailureError, HttpJsonTransport, JobLogClient,
                         JsonTransport, LogRead, MalformedSource, PaginationBudget, ScopeRefused,
                         SourceUnavailable, repository_identity)
from .facts import (CardIdentity, CoverageNote, JobFact, RunFact, StepFact, card_identity,
                    incident_key, parse_run)
from .store import CiFailureStore, Delivery, HeartbeatVerdict, StoreError, WindowStats
from .outlet import BoardOutlet, DrainReport, FilingPlan, OutletConfig, ReconcileReport, Thresholds
from .pipeline import Pipeline, PipelineConfig, Service, TickReport, build_service, environment_config
from .adapter import (AdmissionReceipt, IncidentKeyPlan, KeyTransition, PlatformAdmission,
                      admission_ready, batch_snapshot, build_events, plan_incident_keys,
                      resource_id_for_key)
from .platform_client import PlatformIntake

__all__ = ['ActionsSource', 'AdmissionReceipt', 'BoardClient', 'BoardOutlet', 'CardIdentity',
           'CiFailureError', 'CiFailureStore', 'CoverageNote', 'Delivery', 'DrainReport',
           'HeartbeatVerdict', 'HttpJsonTransport', 'IncidentKeyPlan', 'JobLogClient', 'JsonTransport',
           'JobFact', 'KeyTransition', 'LogRead', 'MalformedSource', 'OutletConfig',
           'PaginationBudget', 'Pipeline',
           'PipelineConfig', 'PlatformAdmission', 'PlatformIntake', 'ReconcileReport', 'RunFact',
           'ScopeRefused', 'Service', 'SourceUnavailable', 'StepFact', 'StoreError', 'Thresholds',
           'TickReport', 'WindowStats', 'admission_ready', 'adapters', 'batch_snapshot',
           'build_events', 'build_service', 'card_identity', 'environment_config', 'incident_key',
           'parse_run', 'plan_incident_keys', 'repository_identity', 'resource_id_for_key']


def adapters() -> tuple[str, ...]:
    """The source names this package may emit events under (sorted, for stable reporting)."""
    from .adapter import SOURCE
    return (SOURCE,)
