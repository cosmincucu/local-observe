"""Freshness-aware operator summary; missing observations are never a healthy zero.

This module reads four observations out of the operator document, not three: `backup`, `jobs` and
`model`, plus `sigma` — the one claim a detection rule pack makes about itself (`shipped`/`measured`/
`unmeasured`, notification budget). The fourth is published by `overview_worker` only when an operator configures
`sigma_artifacts` (overview sigma producer), and an unconfigured deployment is the state this module
exists to represent: it answers `unknown` with three `None`s rather than a green zero, so a pack that
has never been counted is never mistaken for a pack that was counted and quiet.
"""
import datetime as dt
import json
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import timestamp, utc_text
from .state import Store
from .suppression import suppressed_deliveries

#: The triple a `sigma` observation may carry, besides its `headline`. Produced next to the numbers by
#: `sigma_runner.measurement_signal`; validated here because this is the boundary an operator and an
#: agent read, and an observation that does not add up is not a measurement with one field missing.
SIGMA_MEASUREMENT_KEYS = ('shipped', 'measured', 'unmeasured')
#: How long a `sigma` headline may be before it stops being a headline. One number, on the reader side:
#: a producer that publishes more than this gets `unknown`, so the bound cannot drift into the portal.
SIGMA_HEADLINE_MAX = 120


def snapshot(path: Path | str | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            return {}
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get('schema_version') == 1 else {}
    except (OSError, ValueError):
        return {}


def signal(document: dict[str, Any], name: str, now: dt.datetime) -> dict[str, Any]:
    unknown = {'status': 'unknown', 'value': None, 'observed_at': None, 'source': 'not configured'}
    if not document:
        return unknown
    try:
        item = document['signals'][name]
        if not isinstance(item, dict):
            raise ValueError('Expected signal object')
        age = (now-timestamp(item['observed_at'])).total_seconds()
        limit = item['max_age_seconds']
        if type(limit) is not int or not 1 <= limit <= 2678400:
            raise ValueError('Invalid freshness bound')
        state = item['status']
        if state not in ('healthy', 'degraded', 'unknown', 'disabled'):
            raise ValueError('Unknown signal status')
        value = item.get('value')
        if (state in ('healthy', 'degraded') and name in ('backup', 'model')
                and (not isinstance(value, str) or not value.strip())):
            raise ValueError('Available observation requires a value')
        if name == 'jobs' and state not in ('unknown', 'disabled') and (type(value) is not int or value < 0):
            raise ValueError('Expected nonnegative failed-job count')
        if name == 'backup' and value is not None:
            if timestamp(value) > now:
                raise ValueError('Backup verification cannot be in the future')
        if name == 'model' and value is not None and (not isinstance(value, str) or len(value) > 160):
            raise ValueError('Invalid model label')
        if name == 'sigma':
            # notification budget: the pack's own account of how much of it has ever been counted. The arithmetic is
            # checked here because `unmeasured` is the figure a detection-quality gate scores, and a
            # document whose parts do not sum to its whole would make that gate score a fiction. The
            # value is either a complete triple or nothing: a partial one would be read by the caller
            # as a count it never earned.
            if value is None:
                if state in ('healthy', 'degraded'):
                    raise ValueError('Available observation requires the triple')
            elif not isinstance(value, dict) or set(value) != {*SIGMA_MEASUREMENT_KEYS, 'headline'}:
                raise ValueError('Sigma measurement must carry the triple and its headline')
            else:
                if any(type(value[key]) is not int or value[key] < 0 for key in SIGMA_MEASUREMENT_KEYS):
                    raise ValueError('Sigma measurement counts must be nonnegative integers')
                if value['shipped'] != value['measured'] + value['unmeasured']:
                    raise ValueError('Sigma measurement must account for every shipped rule')
                if (not isinstance(value['headline'], str)
                        or not 1 <= len(value['headline']) <= SIGMA_HEADLINE_MAX):
                    raise ValueError('Sigma measurement requires a bounded headline')
        source = item['source']
        if not isinstance(source, str) or not 1 <= len(source) <= 160:
            raise ValueError('Bounded provenance required')
        if not 0 <= age <= limit:
            state, value = 'stale', None
        if state in ('unknown', 'disabled'):
            value = None
        return {'status': state, 'value': value, 'observed_at': item['observed_at'], 'source': source}
    except (OSError, ValueError, KeyError, TypeError):
        return {**unknown, 'source': 'observation unavailable'}


def overview(store: Store, observation_path: Path | str | None = None, *,
             now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or dt.datetime.now(dt.timezone.utc)
    state = store.status()
    document = snapshot(observation_path)
    observations = {name: signal(document, name, now) for name in ('backup', 'jobs', 'model', 'sigma')}
    rules = observations['sigma']['value'] if isinstance(observations['sigma']['value'], dict) else None
    return {'schema_version': 1, 'generated_at': utc_text(now),
        'open_incidents': state['incidents'].get('open', 0),
        'pending_approvals': state['actions'].get('pending', 0),
        'pending_deliveries': sum(state['notifications'].get(key, 0) for key in ('pending', 'sending')),
        'dead_deliveries': state['notifications'].get('dead', 0),
        # Not a field of `Store.status()`: that dict is pinned by `tests/test_regression_schema_version.py`
        # and the `tests/test_overview.py` double, and a new aggregate on the runtime read is a change of
        # its own. `suppressed_deliveries` reads the durable refusal list read-only and answers None when
        # there is no file to read, which is how every other tile on this page says "unknown".
        'suppressed_deliveries': suppressed_deliveries(store),
        'last_verified_backup': observations['backup']['value'],
        'failed_jobs': observations['jobs']['value'], 'resident_model': observations['model']['value'],
        'backup_display': observations['backup']['value'] or observations['backup']['status'].capitalize(),
        'jobs_display': (str(observations['jobs']['value']) if observations['jobs']['value'] is not None
                         else observations['jobs']['status'].capitalize()),
        'jobs_status': observations['jobs']['status'], 'jobs_scope': observations['jobs']['source'],
        'model_display': observations['model']['value'] or observations['model']['status'].capitalize(),
        # Sigma compiler (notification budget): the size of the rule pack, stated as what it has actually been
        # measured over.
        # `sigma_unmeasured` is the number a detection-quality gate scores (corpus eval) and `sigma_shipped`
        # is the denominator it must be read against; a pack that grew without its `measured` figure
        # rising is a pager getting louder, which is the sentence this tile exists to make visible.
        # All three are None whenever the observation is absent, unreadable or past its own bound, and
        # that is what every deployment answers today: the one writer of this document
        # (`platform/overview_worker.py`) publishes `jobs` and `model` only, so the shape has a reader
        # and no producer until a card owns that write. No shipped tile maps these fields, so nothing
        # renders a blank; `/v1/overview` and the `platform_overview` tool serve them.
        'sigma_shipped': rules['shipped'] if rules is not None else None,
        'sigma_measured': rules['measured'] if rules is not None else None,
        'sigma_unmeasured': rules['unmeasured'] if rules is not None else None,
        'sigma_display': (rules['headline'] if rules is not None
                          else observations['sigma']['status'].capitalize()),
        'sigma_status': observations['sigma']['status'], 'sigma_scope': observations['sigma']['source'],
        'signals': observations}
