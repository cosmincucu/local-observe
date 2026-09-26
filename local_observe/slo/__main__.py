"""The looping SLO producer: ``python -m local_observe.slo``, off unless a document names an objective.

One round reads every configured objective through the store facade, judges its error budget and its
burn pair, and files what the judgment earned through ``POST /v1/events``. It is a module main and not a
``lo-platform`` subcommand for the reason every other long-running worker here gives: it reaches the
store and the platform over the network and loops, while ``lo-platform`` is a one-shot operator command
that opens the SQLite file itself. ``lo-platform slo`` is registered (rca) as that one-shot
round, and `alerts.tick` keeps the same signature as `conditions.tick`, which is what made the
registration a few lines rather than a redesign.

The shape is the house shape (`configdrift.main`, `pathcheck.main`), including the two exit codes: no
configuration named is exit 0 with one `INFO` line naming ``LO_SLO_CONFIG`` and nothing opened; a
document that is named and unreadable, a missing producer identity, a missing cursor or a cursor whose
parent an operator has not created is exit 1 with one `WARNING` naming the exception class. A producer
that survived a broken objective document would be reporting "nothing is burning" about budgets it never
opened, which is the one answer this card exists to make impossible.

Each round logs one `INFO` line built from `alerts.summary_line`, so the words a reader of the log sees
are the fields the round actually produces; a failed round logs a `WARNING` and repeats, because the
cursor still holds what was owed — and it repeats **from that file**. The durable cursor is re-read
inside the ownership lock before every round, including the round after a transport refusal and the one
after an event was accepted but its acknowledgement was lost, because `alerts.tick` writes the round's
undelivered batch to that file *before* it POSTs anything: the bytes the file holds are the only bytes
the next round may offer. Carrying the state object from one iteration to the next is the defect
`tests/test_slo_worker_replay.py` exists to keep shut — a round handed the pre-refusal document finds no
pending batch, queries the store again, re-grades the window and saves its freshly-derived events over
the ones still owed, and a re-graded window is a *different* event (another `source_event_id`, a shorter
`expires_at`), not a duplicate the platform can fold. A cursor that proves unreadable, foreign-version or
bound to another rule set mid-run is refused on every round — one `WARNING` naming the exception class,
no store read, no POST — and left byte-for-byte as it was found: this loop never rewrites, truncates or
silently resets state it cannot trust, because the only remedy for those bytes is an operator's. This
process neither reads nor writes a notification mode: whether a burn page reaches a human is decided by
the platform service and its per-channel budget (`platform/notification_safety.py`), as it is for a
Gatus result or a drift report.
"""
from __future__ import annotations

import datetime as dt
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.log import get_logger
from local_observe.platform.cli import store_reader
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import StateError, label

from . import alerts

log = get_logger(__name__)


def cursor_location(environment: Any = None) -> Path:
    """Return this producer's cursor path, refusing anything that is not a place to keep state.

    ``LO_SLO_CURSOR`` is required whenever a configuration is named (`anomaly`'s rule, for `anomaly`'s
    reason: a verdict with nowhere to record what it owes is a verdict that can be lost), it must be
    absolute (a relative path moves when the service manager's working directory moves, and silently
    opening a *different* cursor is worse than not starting), and its parent must already exist — the
    parent is the operator's to create, so a producer never mkdirs its own state directory into the wrong
    place and then believes what it finds there.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(alerts.CURSOR_ENVIRONMENT) or '').strip()
    if not raw:
        raise StateError(f'SLO producer needs {alerts.CURSOR_ENVIRONMENT}: a configured producer cannot '
                         'deliver verdicts it cannot re-send')
    path = Path(raw)
    if not path.is_absolute():
        raise StateError('SLO cursor path must be absolute; a relative path is not a durable location')
    if not path.parent.is_dir():
        raise StateError('SLO cursor parent does not exist; create it before starting')
    return path


def main() -> int:
    """Run the producer loop; exit 0 without touching the network when nothing is configured.

    Identity comes from ``LO_SLO_SOURCE`` and must match the producer token's identity, since the
    platform records who said it; ``LO_INDEX_PATH`` is the built inventory index every objective's
    resource must resolve in, and the series come from the three ``LO_CLICKHOUSE_*`` variables through
    `platform/cli.store_reader` — the one read surface store facade fixed, so a second query transport never
    appears beside it.
    """
    try:
        config = alerts.producer_config()
        if config is None:
            return 0
        cursor_path = cursor_location()
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')
        index_path, source = os.environ['LO_INDEX_PATH'], os.environ[alerts.SOURCE_ENVIRONMENT]
        label(source)
        reader = store_reader(os.environ)
        # Start-up validation, and nothing more: this call owns the exit-1 refusal of a cursor that
        # cannot be trusted to deliver from. The loop re-reads the file before every round (below), and
        # no round is driven from a document loaded at another instant.
        alerts.cursor_document(cursor_path, config)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        # `StateError` and `vocabulary.VocabularyError` are both `ValueError`, and a missing environment
        # value is a `KeyError`: every one of them is a configuration the operator has to fix, and
        # sqlite3.Error because the index is a SQLite file whose absence is an OperationalError.
        log.warning('SLO producer cannot start; configuration is missing or invalid',
                    extra={'error_class': type(exc).__name__})
        return 1

    def deliver(item: dict[str, Any]) -> None:
        if platform.request('POST', '/v1/events', item)[0] != 200:
            raise TransportError('SLO intake refused; the cursor is not advanced')

    log.info('SLO producer started', extra={'objectives': len(config['rules']),
                                            'tick_seconds': config['interval_seconds']})
    with exclusive_owner(cursor_path):
        while True:
            # What this round owes is read from disk here, inside the ownership lock, and nowhere else:
            # a refused round has already saved its batch, so the pending events a replay may deliver are
            # the ones the file holds. A reload that refuses is read-only by construction — `tick` is
            # never reached, so nothing here can overwrite or reset the bytes it could not read.
            try:
                state = alerts.cursor_document(cursor_path, config)
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                log.warning('SLO cursor is unusable; the round is refused and its bytes are untouched',
                            extra={'error_class': type(exc).__name__})
                log.debug('SLO cursor reload failed', exc_info=True)
            else:
                try:
                    summary = alerts.tick(index_path, config, cursor_path, reader, deliver,
                                          now=dt.datetime.now(dt.timezone.utc), state=state)
                except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                    log.warning('SLO delivery unavailable; cursor not advanced, this round repeats',
                                extra={'error_class': type(exc).__name__})
                    log.debug('SLO tick failed', exc_info=True)
                else:
                    log.info('SLO tick finished', extra=alerts.summary_line(summary))
            time.sleep(config['interval_seconds'])


if __name__ == '__main__':
    raise SystemExit(main())
