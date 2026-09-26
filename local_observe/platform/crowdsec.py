"""CrowdSec: read its decisions as state, admit its alerts as events, gate every block (crowdsec).

threat detection engine kept only CrowdSec's *deciding* half — "Local API as decision store + bouncers replace the
hand-rolled router block" — and auto-block authority put every block that is not the VPN path, the LAN gateway or an
ISP range behind a human approval. `docs/COMPONENTS.md` §3 states the same as a treatment: *"Optional;
blocklist opt-in; platform approval and protected destinations enforced"*. This module is where the
third clause becomes code rather than a sentence, and it is deliberately three unrelated things held
together by one component:

1. **An inbound adapter for `event intake`'s normaliser** (`alerts`, registered under source `crowdsec`).
   CrowdSec's own HTTP notification plugin posts its `models.Alert` list to
   `POST /v1/intake/crowdsec`; the payload becomes a canonical `kind='security'` event through the same
   evidence-or-coverage rule as every other source (`docs/CONTRACTS.md` §4.2). No bespoke emitter exists
   here on purpose: the port table's §6 `aiops/ingest` row exists precisely because an agent writing a
   second inbound path gets the evidence rule wrong.
2. **A read-only Local API client** (`LocalApi`). Upstream's own permission model decides this half:
   *"API Keys: they are used to authenticate Remediation Components (bouncers) and can only read
   decisions"*, while login/password (a *machine*) may *"read, create and delete decisions"*
   (`local_api/authentication.md` at v1.8.1). The product therefore ships a reader and ships **no
   writer**: the credential that could create a decision is not one this repository hands out, and the
   write endpoints are listed UNVERIFIED in `components/control/crowdsec/versions.json` rather than
   composed from memory.
3. **The protected-destination gate** (`protected_schema`, `protected_networks`,
   `validate_action_document`). auto-block authority's allowlist lives in the deployment-owned action-policy document
   (`LO_ACTION_POLICY`), so a compromised agent cannot widen it from a request body: that file is
   mounted read-only and read once at service start, and an address inside a protected range simply
   does not validate. The refusal is the one `policy.py` already raises and `refusals.py` already books
   (`Action parameters do not match allowlisted schema` → `policy-parameters-schema`), which is what
   "add no second approval path" costs — nothing new to audit, and nothing new that could be audited
   wrongly. `components/control/crowdsec/CONTRACT.md` states the limit of that choice in one paragraph:
   prefix overlap between two `Range` values is not a pattern property, and there is no writer to catch
   it with, so an over-broad range is caught by a human reading the parameters, not by this code.

Nothing here decides, blocks or enrols. `crowdsec.decision` is deliberately not an event
(`docs/CONTRACTS.md` §4: *"a decision is read state and a block is an approved action"*), the Central
API stays disabled unless the operator opts in (community blocklist dependency), and enrolling a machine ID against it
is a
human, credentialed act with no code path in this repository.
"""
from collections.abc import Iterable, Mapping
import datetime as dt
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from typing import Any
import urllib.parse

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import digest, utc_text
from local_observe.log import get_logger
from . import intake, vocabulary
from .detections import event as build_event
from .state import StateError, identifier, label

log = get_logger(__name__)

__all__ = ['SOURCE', 'ALERTS_KEY', 'MAX_ALERTS', 'UNDECLARED_SCENARIO_COVERAGE', 'alerts', 'register',
           'validate_rules', 'LocalApi', 'client_from_environment', 'DECISIONS_ROUTE',
           'BOUNCER_TOKEN_ENVIRONMENT', 'LAPI_URL_ENVIRONMENT',
           'WRITE_ACTIONS', 'PROTECTED_KEY', 'SHIPPED_PROTECTED_SLOTS', 'write_action_definitions',
           'protected_networks', 'protected_schema', 'protected_from_definition', 'protected_covers',
           'validate_action_document', 'action_request', 'main']

#: The registered intake source name: the segment `POST /v1/intake/<source>` carries, and the `source`
#: field of every event produced. `docs/CONTRACTS.md` §4 and `vocabulary.SOURCE_VOCABULARIES` already
#: name `crowdsec`, so this adds a producer to an existing word rather than a new word.
SOURCE = 'crowdsec'

#: How many `models.Alert` objects one notification may carry. The route's 64 KiB body ceiling bounds
#: the bytes; this bounds the incidents one POST can open. Refused whole, never truncated: a silently
#: dropped alert is an outage this tool manufactured. Equal to `intake.MAX_ENVELOPE_ALERTS` on purpose
#: (one envelope is one page of work for the operator whichever source sent it) and pinned equal by a
#: test rather than aliased, because a source's bound is allowed to move alone.
MAX_ALERTS = 50

#: The single key a notification body may wrap the alert array in, so the array can survive a transport
#: that refuses a bare array as a body. Not a new envelope: `{{.|toJson}}` inside `"{"alerts": ...}"`.
ALERTS_KEY = 'alerts'

#: Explicit selector for models.Alert.events_count (a non-negative int32 at the pinned v1.8.1).
NATIVE_COUNT_FIELD = 'alert.events_count'
MAX_NATIVE_EVENTS_COUNT = 2 ** 31 - 1

#: Per-alert bounds, all of them well above what upstream writes at v1.8.1. A `models.Alert` carries a
#: handful of events and a short scenario name; a payload over these numbers is a caller that has lost
#: the plot, not a rule an operator wrote.
MAX_EVENTS_PER_ALERT = 50
MAX_META_PER_EVENT = 20
MAX_TEXT_CHARS = 256
#: `state.label` bounds every identifier this module emits at 128 characters, so a longer scenario
#: name could not become a rule identity even if a rule existed for it.
MAX_SCENARIO_CHARS = 128
MAX_UUID_CHARS = 64

#: The coverage rule this adapter owns for a scenario nobody declared. A fixed string, never derived
#: from a scenario name: identity that moves when an operator edits their hub collection is the
#: `derive_dedup_key` defect `docs/CONTRACTS.md` §4 refuses, and `intake` makes the same choice for its
#: own two intake gaps (`UNDECLARED_RULE_COVERAGE`, `SEVERITY_REFUSED_COVERAGE`).
UNDECLARED_SCENARIO_COVERAGE = 'crowdsec.undeclared-scenario.coverage'

# --------------------------------------------------------------------- inbound: the alert envelope


def _bounded_text(value: Any, field: str, position: int, maximum: int) -> str:
    """One required string field of the payload, bounded, or a refusal of the whole envelope.

    Raises:
        StateError: The value is not a string of `1..maximum` characters. Never a partial admit: rule 3
            of `intake.py`'s docstring is that a malformed payload is refused rather than degraded,
            because intake opens an incident for any firing event.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise StateError(f'CrowdSec alert {position} carries an unusable {field}')
    return value


def _moment(value: Any, field: str, position: int) -> dt.datetime:
    """One CrowdSec timestamp (`start_at`, `stop_at`) as an aware instant.

    Upstream writes RFC 3339 with nanoseconds and an offset (`2026-09-03T11:44:51.426519652Z`), which
    `datetime.fromisoformat` reads natively on the supported Python. A naive value is refused rather
    than assumed UTC: a window with no zone is a window nobody can compare to the platform clock.

    Raises:
        StateError: The field is absent, not text, naive, or unparseable.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise StateError(f'CrowdSec alert {position} carries an unusable {field}')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise StateError(f'CrowdSec alert {position} carries an unparseable {field}') from None
    if parsed.tzinfo is None:
        raise StateError(f'CrowdSec alert {position} carries a naive {field}')
    return parsed.astimezone(dt.timezone.utc)


def _optional_moment(value: Any, field: str, position: int) -> dt.datetime | None:
    """One optional timestamp field, with upstream's zero time read as *absent* and never as year 1.

    Raises:
        StateError: The value is present and `_moment` refuses it.
    """
    if value is None or (isinstance(value, str) and value.strip().startswith(intake.ZERO_TIME_PREFIX)):
        return None
    return _moment(value, field, position)


def _meta(event: Any, position: int) -> dict[str, str]:
    """The `events[].meta` key/value pairs as one mapping, last value winning, bounded.

    `models.Event` is `{timestamp, meta:[{key,value}]}` and every value is text, including the numeric
    ones supplied by custom metadata. A repeated key is upstream's ambiguity to have; last-wins is stated
    here so a reader knows which one was judged.

    Raises:
        StateError: The event is not an object, `meta` is missing or oversized, or an entry is not a
            bounded key/value pair.
    """
    if not isinstance(event, dict) or not isinstance(event.get('meta'), list):
        raise StateError(f'CrowdSec alert {position} carries an event with no meta list')
    if len(event['meta']) > MAX_META_PER_EVENT:
        raise StateError(f'CrowdSec alert {position} exceeds the per-event meta bound')
    out: dict[str, str] = {}
    for item in event['meta']:
        if not isinstance(item, dict) or set(item) != {'key', 'value'}:
            raise StateError(f'CrowdSec alert {position} carries an unusable meta entry')
        key, value = item['key'], item['value']
        if (not isinstance(key, str) or not 1 <= len(key) <= MAX_TEXT_CHARS
                or not isinstance(value, str) or len(value) > MAX_TEXT_CHARS):
            raise StateError(f'CrowdSec alert {position} carries an unbounded meta entry')
        out[key] = value
    return out


def _sample_value(raw: str) -> int | float | bool | None:
    """A storable value out of a meta string, or `None` when it is not one.

    The rule is `intake`'s private `_sample_value`, restated as a copy rather than an import of a
    private name: a number is a float, `true`/`false` in any case is a boolean, and everything else —
    `nan`, `inf`, empty, a 400-character template string — is nothing, and nothing becomes coverage.
    `tests/test_crowdsec_intake.py` pins the two parsers equal over a table of inputs, which is the
    same device `suppression.condition_key` uses for its copy of an `intake` expression (see
    DEPENDENCIES.md's suppression row: an allowlist that will not let the shared helper be extracted).

    Returns:
        `None` for text that is not a finite number or a boolean word. Never raises: this value comes
        from a payload, and a payload is not obliged to carry a measurement.
    """
    text = raw.strip()
    if not text or len(text) > intake.MAX_SAMPLE_CHARS:
        return None
    folded = text.lower()
    if folded in ('true', 'false'):
        return folded == 'true'
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def _identity(built: dict[str, Any], tie_breaker: str) -> dict[str, Any]:
    """Set `source_event_id` on one **verdict** the factory just built, keyed on the alert's own `uuid`.

    `detections.event` derives identity from `(rule_id, rule_version, resource_id, window)`, which
    collides for CrowdSec in a way it does not collide for a re-evaluated rule: two distinct
    brute-force alerts against one address in one window share a rule, a resource and a window, and
    differ only in their own `uuid` and their event count. Under the factory identity the second
    arrives as `Event retry changed contents` and the whole envelope 400s behind it, so the alert's
    `uuid` joins the identity — the one-line amendment `intake._stamp` makes for a different collision
    (the firing/resolved pair, which has no uuid to tell it apart).

    A `uuid` is admissible where a `fingerprint` is not: it is minted per alert and never derived from
    label or scenario text, so re-posting *the same* notification reproduces it (`accepted` →
    `duplicate`) while renaming a scenario cannot rewrite history. That is `docs/CONTRACTS.md` §4's own
    test, applied to a field this source happens to carry. It is also what makes the §5 "replay does not
    multiply findings" clause true here by construction rather than by hope.

    Raises:
        StateError: The tie-breaker is not a bounded label.
    """
    label(tie_breaker)
    built['source_event_id'] = digest([SOURCE, built['rule_id'], built['rule_version'],
                                       built['resource_id'], built['window']['start'],
                                       built['window']['end'], tie_breaker])
    return built


def _coverage(rule_id: str, resource_id: str | None, window: Mapping[str, str], status: str,
              version: str, watched: str, link: str) -> intake.Prepared:
    """A statement about this intake source or this declared rule, in `detections.evaluate`'s shape.

    `source-heartbeat` references nothing the payload had to carry: the platform's own receipt of this
    source *is* the evidence, which is what makes this form legal where a synthesised sample would not
    be (§6 `aiops/ingest`: an adapter may not invent an evidence reference to data it did not capture).

    Identity is `intake.retry_identity`'s — rule, version, resource, window, **status** — and not the
    verdict's uuid key, on purpose: one gap in one window is one row however many alerts repeat it
    (§5's "replay does not multiply findings", applied to the coverage half), while the `status` half
    keeps a rule's coverage `firing` (nothing keepable arrived) and `resolved` (a reading arrived) from
    becoming one row rewriting the other, which is the same reason `intake` puts `status` in its own
    identity for the firing/resolved pair.
    """
    built = build_event(SOURCE, resource_id, rule_id, 'coverage', status, dict(window),
                        {'rule_id': watched}, query_type='source-heartbeat', version=version)
    built['source_event_id'] = intake.retry_identity(built)
    return intake.Prepared(built, None, link)


def _window(start: dt.datetime, stop: dt.datetime | None, seconds: int,
            now: dt.datetime, position: int) -> tuple[dict[str, str], str]:
    """The window this alert speaks about, and the instant it was observed at — from the payload alone.

    `start_at`/`stop_at` are the scenario's own evaluation span, so unlike the Alertmanager path this
    source carries both ends and nothing has to be invented. A missing `stop_at` reads as
    `start_at + window_seconds` — the declared span, the same reading `intake._window` gives a firing
    alert — and never as "open forever", which no admitted window may be. A re-post must reproduce the
    same bytes to fold into the row `Store.intake` already holds, so any window that slid forward with
    the clock would turn every retry into a fresh incident.

    Raises:
        StateError: A window ending before it starts, ending more than `CLOCK_SKEW_SECONDS` ahead of
            `now`, or spanning more than the seven days `state.validate_event` admits.
    """
    limit = now + dt.timedelta(seconds=intake.CLOCK_SKEW_SECONDS)
    end = stop if stop is not None else start + dt.timedelta(seconds=seconds)
    if end <= start:
        raise StateError(f'CrowdSec alert {position} ends before it starts')
    if end > limit:
        raise StateError(f'CrowdSec alert {position} carries a future observed_at')
    if end - start > dt.timedelta(seconds=intake.MAX_WINDOW_SECONDS):
        raise StateError(f'CrowdSec alert {position} exceeds the bounded evaluation window')
    return {'start': utc_text(start), 'end': utc_text(end)}, utc_text(end)


def _finding_evidence(row: Mapping[str, Any], meta: Mapping[str, str], resource_id: str | None,
                      window: Mapping[str, str], observed_at: str, alert: Mapping[str, Any]
                      ) -> tuple[dict[str, Any] | None, str, dict[str, str]]:
    """`(sample, query_type, parameters)` for one verdict: the reading the alert carried, or the heartbeat.

    The sample is a number *this alert measured* (an event count, a leak speed), referenced as
    `observed-snapshot` and never `metric-threshold`: this process compared nothing to a limit, the
    scenario did, and naming a judgement nobody made is what evidence exists to prevent. `sample_id`
    names the reading (rule, resource, window, instant, value) so re-posting one notification folds
    into the row `Store.put_evidence` already holds instead of refusing it.
    """
    field = row.get('sample_field')
    if field == NATIVE_COUNT_FIELD:
        raw = alert.get('events_count')
        value = raw if type(raw) is int and 0 <= raw <= MAX_NATIVE_EVENTS_COUNT else None
    else:
        raw = meta.get(field) if isinstance(field, str) else None
        value = _sample_value(raw) if isinstance(raw, str) else None
    if value is None:
        return None, 'source-heartbeat', {'rule_id': row['rule_id']}
    sample_id = digest([SOURCE, row['rule_id'], row['rule_version'], resource_id,
                        window['start'], window['end'], observed_at, value])
    return ({'sample_id': sample_id, 'observed_at': observed_at, 'ok': True, 'value': value},
            'observed-snapshot', {'rule_id': row['rule_id'], 'sample_id': sample_id})


def _name_hint(scenario: str) -> str:
    """A loggable, bounded hint of a scenario name that no event may ever carry.

    `intake._name_hint`'s rule, so an operator can find which row to declare whichever source posted.
    Not an identifier and not a condition: renaming the upstream scenario changes a log line, never an
    incident.
    """
    out: list[str] = []
    for character in scenario.lower():
        if character.isalnum():
            out.append(character)
        elif not out or out[-1] != '.':
            out.append('.')
    return ''.join(out)[:64].strip('.') or 'unnamed'


def _alert(alert: Any, position: int, *, rows: Mapping[str, Mapping[str, Any]], now: dt.datetime,
           links: intake.Links) -> list[intake.Prepared]:
    """The events one `models.Alert` produces: a verdict plus its coverage, or coverage alone.

    Same shape as `intake._alert`, for the same reason: which of the two it is comes down to one
    question — did this payload carry a reading this platform can keep? Two differences are real and
    stated here rather than in a footnote.

    * **No resolution transition exists in this source.** The notification plugin fires on new alerts
      and never on a decision's expiry, so nothing this function returns can carry
      `status='resolved'`. An incident opened by a CrowdSec finding is closed by the platform's own
      judgement or by a human, not by a message from CrowdSec — the sentence `CONTRACT.md` must contain
      so nobody writes an "auto-close" adapter that invents transitions.
    * **Loudness and kind are not the operator's to choose.** `crowdsec` declares no severity words
      (`vocabulary.SOURCE_VOCABULARIES`, `docs/CONTRACTS.md` §4's crosswalk table: *"a CrowdSec alert is
      a scenario"*), so no severity argument is ever passed and the factory's `warning`-for-firing
      stands. Its type space is closed with one verdict word, `alert` → `security`, so the kind comes
      from the crosswalk and a rule row claiming another kind is a configuration error refused here,
      not honoured.

    The `rule_id` is the declared row's, not `classify`'s `condition`: `docs/CONTRACTS.md` §4 is
    explicit that for a CrowdSec scenario, as for a Sigma rule, "the crosswalk names the *channel*, not
    the rule", and `sigma_runner` already composes its rule identity that way.
    """
    if not isinstance(alert, dict):
        raise StateError(f'CrowdSec alert {position} is not an object')
    scenario = _bounded_text(alert.get('scenario'), 'scenario', position, MAX_SCENARIO_CHARS)
    alert_uuid = _bounded_text(alert.get('uuid'), 'uuid', position, MAX_UUID_CHARS)
    start = _moment(alert.get('start_at'), 'start_at', position)
    stop = _optional_moment(alert.get('stop_at'), 'stop_at', position)
    source = alert.get('source')
    if not isinstance(source, dict):
        raise StateError(f'CrowdSec alert {position} carries no source object')
    _bounded_text(source.get('scope'), 'source.scope', position, MAX_TEXT_CHARS)
    value = _bounded_text(source.get('value'), 'source.value', position, MAX_TEXT_CHARS)
    events = alert.get('events')
    if events is None:
        events = []
    if not isinstance(events, list):
        raise StateError(f'CrowdSec alert {position} carries an events value that is not a list')
    if len(events) > MAX_EVENTS_PER_ALERT:
        raise StateError(f'CrowdSec alert {position} exceeds the per-alert event bound')

    row = rows.get(scenario)
    seconds = row['window_seconds'] if row else intake.MIN_WINDOW_SECONDS
    window, observed_at = _window(start, stop, seconds, now, position)
    resource_id, link = links.resolve({'instance': value})

    if row is None:
        log.warning('CrowdSec alert names no declared scenario; filing coverage about the intake source',
                    extra={'source': SOURCE, 'rule_id': UNDECLARED_SCENARIO_COVERAGE,
                           'alert': position, 'name_hint': _name_hint(scenario)})
        return [_coverage(UNDECLARED_SCENARIO_COVERAGE, resource_id, window, 'firing',
                          intake.DEFAULT_RULE_VERSION, SOURCE, link)]

    version = row['rule_version']
    kind = vocabulary.classify(SOURCE, 'alert')[0]
    if row['kind'] != kind:
        raise StateError(f'CrowdSec rule {row["rule_id"]} declares a kind this source\'s vocabulary '
                         f'does not allow; only {kind} is admissible')
    meta: dict[str, str] = {}
    for event in events:
        meta.update(_meta(event, position))
    sample, query_type, parameters = _finding_evidence(row, meta, resource_id, window, observed_at, alert)
    if sample is None:
        log.warning('CrowdSec alert carried no keepable reading; filing coverage instead of a verdict',
                    extra={'source': SOURCE, 'rule_id': row['rule_id'] + '.coverage', 'alert': position})
        return [_coverage(row['rule_id'] + '.coverage', resource_id, window, 'firing', version,
                          row['rule_id'], link)]
    finding = build_event(SOURCE, resource_id, row['rule_id'], kind, 'firing', dict(window), parameters,
                          query_type=query_type, observed_at=observed_at, version=version)
    return [_coverage(row['rule_id'] + '.coverage', resource_id, window, 'resolved', version,
                      row['rule_id'], link),
            intake.Prepared(_identity(finding, alert_uuid), sample, link)]


def alerts(payload: Any, *, now: dt.datetime, index_path: Any = None,
           rules: Mapping[str, Any] | None = None) -> list[intake.Prepared]:
    """Map one CrowdSec notification body onto canonical events, one `models.Alert` each.

    Upstream renders the notification body from the plugin's `format` template over a **list** of
    `models.Alert` objects — its shipped default is `format: |` + `{{.|toJson}}`
    (`cmd/notification-http/http.yaml` at v1.8.1), whose output "goes in the http request body". This
    platform's transport will not carry that rendering: the POST handler answers 400
    `Expected a JSON object body` for any body that is not a JSON object (`api.py`, one branch guarding
    every write route, because each of them reads named fields). So the two shapes accepted here are the
    one the route can deliver — an object whose single key holds that array, which is what
    `examples/crowdsec/http-notification.yaml` makes the template emit — and the bare array itself, for a
    fixture read off a disk with no transport in front of it. Wrapping is the operator's template, not a
    new product envelope: nothing here invents a field.

    Fields read: `scenario`, `uuid`, `start_at`, `stop_at`, `source.scope`/`source.value`, and the one
    native `events_count` when `sample_field` is `alert.events_count`, or the `events[].meta` pair
    selected by any other `sample_field`. The native count must be an integer in 0..2147483647;
    booleans, strings, fractional values and missing counts produce coverage only. The count is never
    inferred from the retained event details. Fields ignored, each with its
    reason in `components/control/crowdsec/CONTRACT.md`: `remediation`/`simulated` (whether CrowdSec
    asked somebody to block is not a statement about whether the behaviour happened), `decisions[]`
    (read state, queried through `LocalApi`, never copied onto an event), `machine_id`, `labels`,
    `message`, `scenario_hash`, the top-level `capacity`, and the GeoIP
    conveniences (`cn`, `as_number`) — a canonical event has fourteen fields and
    `state.validate_event` admits six evidence parameter names, so a field with no home here is dropped
    rather than smuggled into one that means something else.

    Raises:
        StateError: The payload is neither form above, carries no alert or more than `MAX_ALERTS` of
            them, or any alert of it is malformed. Nothing is admitted from a refused payload.
    """
    rows = dict(rules) if isinstance(rules, Mapping) else {}
    if not rows:
        raise StateError(f'No intake rules are configured for source {SOURCE}; nothing was admitted')
    if isinstance(payload, Mapping) and set(payload) == {ALERTS_KEY}:
        payload = payload[ALERTS_KEY]
    if not isinstance(payload, list):
        raise StateError(f'CrowdSec payload must be an alert array, or an object with one {ALERTS_KEY!r} '
                         'key holding it')
    if not 1 <= len(payload) <= MAX_ALERTS:
        raise StateError(f'CrowdSec payload must carry between 1 and {MAX_ALERTS} alerts')
    with intake.Links(index_path) as links:
        produced: list[intake.Prepared] = []
        for position, item in enumerate(payload):
            produced.extend(_alert(item, position, rows=rows, now=now, links=links))
        return produced


def register() -> None:
    """Bind `alerts` to the `crowdsec` source, once, and stay importable twice.

    Idempotent because `intake.register` refuses a second adapter for one source, and an import that
    could break the platform service's start-up is a worse defect than a duplicate registration. This
    module is imported by `api.app_factory` for exactly this side effect, the way `intake.py` registers
    its own Alertmanager adapter at the foot of the file.

    Raises:
        StateError: `intake` refuses the name, which would mean `crowdsec` is no longer a bounded
            identifier and every other use of it in the tree is broken too.
    """
    if SOURCE not in intake.adapters():
        intake.register(SOURCE, alerts)


def validate_rules(document: Any) -> dict[str, dict[str, Any]]:
    """`intake.validate_rules` for this document, plus the one rule this source cannot bend.

    A `crowdsec` row may not name a kind other than the vocabulary's verdict word for this source:
    `alertmanager` takes its kind from its rules because its `alertname` space is open, and `crowdsec`'s
    is closed. Call this at authoring time (`python -B -m local_observe.platform.crowdsec
    --check-rules FILE`); the adapter re-checks the same thing per alert, but a refusal that arrives at
    the first webhook is a worse day than a refusal at boot.

    Returns:
        `intake.validate_rules`' mapping, unchanged.

    Raises:
        StateError: Whatever `intake.validate_rules` raises, or a `crowdsec` row naming another kind.
    """
    result = intake.validate_rules(document)
    verdict = vocabulary.classify(SOURCE, 'alert')[0]
    for name, row in result.get(SOURCE, {}).items():
        if row['kind'] != verdict:
            raise StateError(f'CrowdSec intake rule {name} declares a kind outside this source\'s '
                             f'closed vocabulary; declare {verdict}')
    return result


# ------------------------------------------------------------------ the Local API: read-only


#: The route the pinned release answers decisions on, and the header its key travels in — both quoted
#: from `local_api/bouncers-api.md` at v1.8
#: (`curl -H "X-Api-Key: …" localhost:8080/v1/decisions`), which is also where the `null`-for-no-match
#: answer handled in `_decision_rows` comes from. The endpoints that *create* a decision are
#: deliberately absent: they are machine-authenticated, and this repository ships no machine credential
#: and no caller for them (versions.json records them as UNVERIFIED, not as guessed paths).
DECISIONS_ROUTE = '/v1/decisions'
#: Where the URL and the key come from. `read_credential` prefers `LO_CROWDSEC_BOUNCER_TOKEN_FILE`, and
#: `scripts/check_foundation.py::check_credential_files` refuses a `LO_*_TOKEN` environment value in any
#: manifest it walks, so the mounted file is the only form a shipped manifest may carry.
BOUNCER_TOKEN_ENVIRONMENT = 'LO_CROWDSEC_BOUNCER_TOKEN'
LAPI_URL_ENVIRONMENT = 'LO_CROWDSEC_LAPI_URL'

#: The response bound. `GET /v1/decisions` unfiltered returns every live decision, and a Community
#: Blocklist subscription makes that a large number; `JsonClient` already caps the bytes at 4 MiB, and
#: this is the count-side bound that keeps "how many did you read?" answerable.
MAX_DECISIONS = 2000
#: `pkg/models/decision.go` at v1.8.1, field for field. A key outside this set means an upstream
#: version move and a re-read, not a free pass through to a human's approval screen.
MAX_DECISION_FIELDS = frozenset({'duration', 'id', 'origin', 'scenario', 'scope', 'simulated',
                                 'type', 'until', 'uuid', 'value'})

PROTECTED_KEY = 'protected_destinations'
#: Octet-aligned IPv4 prefixes only; `protected_networks` says why a `/17` is refused rather than
#: silently widened.
IPV4_ALIGNED = (8, 16, 24, 32)
MAX_PROTECTED_NETWORKS = 32
MAX_ACTION_DOCUMENT_BYTES = 65536
#: The two action names whose parameters carry an address somebody is about to be blocked for. Only
#: these are required to declare a protected list — a read-only action has nothing to protect.
WRITE_ACTIONS = ('crowdsec-decision-apply', 'crowdsec-decision-remove')
#: The shipped example's three protected slots, as documentation ranges (RFC 5737). They cannot be
#: anyone's real VPN path, gateway or ISP network, so an operator who never edits the file blocks
#: nothing at all: the failure mode is a useless component, not a locked-out estate.
SHIPPED_PROTECTED_SLOTS = ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')


class LocalApi:
    """Read CrowdSec's decisions through one bouncer API key. Nothing else.

    Deliberately narrow, because upstream's permission model is narrow: an API key "can only read
    decisions". There is no `add_decision`, no `delete_decisions` and no login/password path on this
    object — creating a decision needs a *machine* credential, and a class that could read and write
    would make "does this deployment hold the power to block?" a question about a file nobody has read.
    `components/control/crowdsec/CONTRACT.md` names what would have to be decided before a writer
    exists, and why its absence is tolerated rather than overlooked.
    """

    def __init__(self, base_url: str, token: str, *, allow_http: bool = False,
                 timeout: int = 10) -> None:
        """Bind one Local API endpoint. The key rides `X-Api-Key`, never `Authorization`.

        `JsonClient(base, None)` is that transport's documented no-Authorization-header mode; handing
        the key per request is what keeps it from being sent twice under two header names. The client's
        own rules still apply and are not loosened here: HTTPS unless `allow_http=True` declares the
        flat project network, no redirects (a credential never follows a 302), no credentials embedded
        in the URL, 4 MiB response ceiling.

        Raises:
            TransportError: The token is blank, or `base_url` is not an endpoint `JsonClient` accepts.
        """
        if not isinstance(token, str) or not token.strip():
            raise TransportError('A bounded Local API credential is required')
        self.client = JsonClient(base_url, None, allow_http=allow_http, timeout=timeout)
        self.token = token

    def decisions(self, *, ip: str | None = None, cidr: str | None = None,
                  scope: str | None = None, value: str | None = None) -> list[dict[str, Any]]:
        """Every live decision this endpoint reports, or the ones matching one address, range or scope.

        Args:
            ip: An IPv4/IPv6 address to ask about (upstream's `ip=`, which also answers with the
                ranges *containing* it — a real decision about a host, not a miss).
            cidr: A prefix to ask about (upstream's `range=`). Bare addresses use their host prefix:
                `/32` for IPv4 and `/128` for IPv6.
            scope: With `value`, a non-IP decision axis; `username` is upstream's own example.
            value: That scope's value; refused without `scope`.

        The four query keys are upstream's, read at v1.8.1 from the client library its own bouncers
        compile against: `pkg/apiclient/decisions_service.go::DecisionsListOpts` tags `scope`, `value`,
        `type`, `ip`, `range` and `contains` onto `GET /v1/decisions`. `type=` is not sent because this
        component's vocabulary has one decision type to look for (`ban`) and asking for another would be
        a claim about a verdict this product cannot make; `contains=` is not sent because `ip=` already
        answers with containing ranges upstream, and two ways to ask one question is how a reader ends up
        trusting the wrong one.

        Returns:
            Defensive dicts, at most `MAX_DECISIONS`, each holding only `MAX_DECISION_FIELDS` keys with
            bounded string (or integer `id`, boolean `simulated`) values. Upstream answers `null` when
            nothing matches, which reads as `[]` here: an empty answer from an endpoint that answered
            200 is a real answer, and an error must never be mistaken for one.

        Raises:
            StateError: The filters are contradictory, unparseable or oversized, or the answer carries a
                field shape this contract has not read at the pinned version. A surprising response is
                a refusal rather than a partial parse, because the caller is a human about to approve
                something that blocks an address.
            TransportError: The endpoint is unreachable, refused it, or answered non-JSON.
        """
        asked = [name for name, given in (('ip', ip), ('range', cidr), ('scope', scope)) if given is not None]
        if len(asked) > 1 or (value is not None and scope is None):
            raise StateError('Ask the Local API about one address, one range or one scope at a time')
        query: dict[str, str] = {}
        if ip is not None:
            query['ip'] = _address_text(ip, 'ip')
        if cidr is not None:
            query['range'] = _address_text(cidr, 'range', prefix=True)
        if scope is not None:
            query['scope'] = _label_text(scope, 'scope')
            query['value'] = _label_text(value, 'value')
        path = DECISIONS_ROUTE + ('?' + urllib.parse.urlencode(query) if query else '')
        status, answer = self.client.request('GET', path, headers={'X-Api-Key': self.token})
        if status != 200:
            raise TransportError('The Local API refused the decision read')
        return _decision_rows(answer)

    def covers(self, address: str) -> bool:
        """Whether CrowdSec currently holds a decision reaching `address` — a read, never a verdict.

        A range decision containing the address counts, because upstream answers it on `ip=` and a ban
        of the /24 *is* a ban of the host. `False` on an empty list, which is the only reason this needs
        a name: "no decision" and "no answer" are different facts, and this method can only report the
        first (`TransportError` reports the second).

        Raises:
            StateError: `address` is not a literal address.
        """
        return bool(self.decisions(ip=_address_text(address, 'ip')))


def _address_text(value: Any, field: str, *, prefix: bool = False) -> str:
    """A validated address or prefix, normalised to text that is safe in a query string.

    `prefix=True` is upstream's `range=`, which wants a prefix: a bare address is asked as its own host
    prefix, and a prefix with host bits set (`192.0.2.7/24`) is refused rather than silently rewritten to
    the containing network — an answer to a question nobody asked is worse than an error, because a human
    is about to act on it. Without `prefix` (`ip=`) a prefix is refused outright for the same reason.

    The shape of this function is a trap in this repository: `StateError` subclasses `ValueError`
    (`state.py`), so a refusal raised inside a `try: … except ValueError` becomes the parser's message
    and the operator loses the sentence that named the fix. Every refusal here is therefore outside the
    block that converts `ValueError`.

    Raises:
        StateError: Not a bounded literal address (or prefix, with `prefix=True`), a prefix where an
            address belongs, or a prefix with host bits set.
    """
    if not isinstance(value, str) or not 3 <= len(value) <= 45:
        raise StateError(f'Local API {field} filter is not a bounded address')
    if '/' in value:
        try:
            network: Any = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise StateError(f'Local API {field} filter is not a prefix') from None
        if not prefix:
            raise StateError(f'Local API {field} filter takes one address; ask about {network} as a range')
        host, _, _ = value.partition('/')
        if ipaddress.ip_address(host) != network.network_address:
            raise StateError(f'Local API {field} filter names a host inside a prefix; ask for '
                             f'{network} or for the host alone')
        return str(network)
    try:
        address: Any = ipaddress.ip_address(value)
    except ValueError:
        raise StateError(f'Local API {field} filter is not an address') from None
    return f'{address}/{address.max_prefixlen}' if prefix else str(address)


def _label_text(value: Any, field: str) -> str:
    """A bounded `scope`/`value` token for a query string.

    Raises:
        StateError: Not a bounded label, restated with the field's name.
    """
    try:
        return label(value)
    except StateError:
        raise StateError(f'Local API {field} filter is not a bounded token') from None


def _decision_rows(answer: Any) -> list[dict[str, Any]]:
    """The decision array upstream answered, as bounded defensive dicts.

    Raises:
        StateError: The answer is not a list of bounded decision objects within `MAX_DECISIONS`, or one
            of its entries carries a key `MAX_DECISION_FIELDS` has not read at the pinned version.
    """
    if answer is None:
        return []
    if not isinstance(answer, list) or len(answer) > MAX_DECISIONS:
        raise StateError('The Local API answered a decision list this contract cannot bound')
    rows: list[dict[str, Any]] = []
    for item in answer:
        if not isinstance(item, dict) or set(item) - MAX_DECISION_FIELDS:
            raise StateError('The Local API answered a decision field this contract has not read')
        row: dict[str, Any] = {}
        for name, given in item.items():
            if name == 'id':
                if isinstance(given, bool) or not isinstance(given, int):
                    raise StateError('The Local API answered a decision id that is not an integer')
            elif name == 'simulated':
                if not isinstance(given, bool):
                    raise StateError('The Local API answered a simulated flag that is not a boolean')
            elif not isinstance(given, str) or not 1 <= len(given) <= MAX_TEXT_CHARS:
                raise StateError('The Local API answered an unbounded decision value')
            row[name] = given
        rows.append(row)
    return rows


def client_from_environment(environ: Mapping[str, str] | None = None) -> LocalApi | None:
    """This process's read-only Local API client, or `None` when no endpoint is configured.

    An unset `LO_CROWDSEC_LAPI_URL` is the documented off switch and logs one INFO line naming the
    variable — the shape every optional producer here takes (`LO_DRIFT_CONFIG`, `LO_ANOMALY_CONFIG`,
    `LO_INTAKE_RULES`). Off is loud in the direction that matters: no decision can be read, so nothing
    can be approved *for* blocking either, because a proposal citing a decision nobody can show is
    refused by `action_request` long before it reaches the store.

    Raises:
        StateError: The URL is set and the credential is missing or unreadable, or either is refused by
            its own reader.
    """
    environ = {} if environ is None else environ
    url = (environ.get(LAPI_URL_ENVIRONMENT) or '').strip()
    if not url:
        log.info('CrowdSec decision reads are off', extra={'variable': LAPI_URL_ENVIRONMENT})
        return None
    try:
        token = read_credential(BOUNCER_TOKEN_ENVIRONMENT, environ=environ)
    except (KeyError, OSError, ValueError) as exc:
        raise StateError('CrowdSec endpoint configured without a readable bouncer credential at '
                         f'{BOUNCER_TOKEN_ENVIRONMENT}_FILE') from exc
    return LocalApi(url, token, allow_http=environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')


# ----------------------------------------------------------- protected destinations (auto-block authority)


def protected_networks(cidrs: Iterable[str]) -> list[Any]:
    """Parse a protected-destination list into networks, refusing anything not expressible as one.

    The list is the deployment's, from `LO_ACTION_POLICY` — which is why an agent that has convinced the
    platform to propose a block cannot widen it: the file is mounted read-only, read once at service
    start by `api.app_factory`, and no request body reaches it.

    Two limits, both in the safe direction and both named in the refusal rather than discovered later:

    * **IPv4 must be octet-aligned** (`/8`, `/16`, `/24`, `/32`). The enforcement point is a JSON Schema
      pattern (see `protected_schema`), and a `/17` has no pattern that is both sound and nameable by a
      human editing YAML at 2am; the refusal names the aligned prefix to write instead, which protects
      more than asked — the direction auto-block authority's own failure mode (locked out of the VPN) prefers.
    * **Any IPv6 entry refuses every IPv6-shaped value.** Prefix containment in compressed IPv6 text is
      not a pattern property, so this protects the whole family rather than silently under-protecting
      the gateway's `fe80::` address. If that is too blunt for a real deployment, the fix is a writer
      that runs `protected_covers`, not a cleverer regex.

    Raises:
        StateError: The list is empty, oversized, holds a non-string, a malformed prefix, or a
            non-aligned IPv4 prefix.
    """
    rows = list(cidrs)
    if not rows:
        raise StateError('A protected destination list must name at least one network')
    if len(rows) > MAX_PROTECTED_NETWORKS:
        raise StateError(f'A protected destination list may name at most {MAX_PROTECTED_NETWORKS} networks')
    networks: list[Any] = []
    for entry in rows:
        if not isinstance(entry, str) or not 3 <= len(entry) <= 49:
            raise StateError('A protected destination must be a CIDR string')
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise StateError(f'A protected destination is not a CIDR network: {entry}') from None
        if network.version == 4 and network.prefixlen not in IPV4_ALIGNED:
            aligned = network.supernet(new_prefix=(network.prefixlen // 8) * 8)
            raise StateError(f'A protected IPv4 destination must be octet-aligned; write {aligned} '
                             f'instead of {entry}, which protects more and never less')
        networks.append(network)
    return networks


def _v4_pattern(network: Any) -> str:
    """The anchored text prefix of an aligned IPv4 network.

    A `/32` keeps its delimiters (`^192\\.0\\.2\\.7($|[/])`) so a protected host is refused as an `Ip`
    value and as the leading text of a `Range` value, while `192.0.2.70` stays allowed — a prefix that
    refused a neighbour would be over-protection wearing a disguise.
    """
    if network.prefixlen == 32:
        return f'^{re.escape(str(network.network_address))}($|/)'
    octets = str(network.network_address).split('.')
    keep = network.prefixlen // 8
    return '^' + '\\.'.join(octets[:keep]) + ('\\.' if keep < 4 else '$')


def protected_schema(cidrs: Iterable[str]) -> dict[str, Any]:
    """The JSON Schema fragment refusing every protected address, generated from the operator's list.

    `{"not": {"anyOf": [{"pattern": …}, …]}}`, one pattern per protected network, from the same list
    `protected_networks` validated so the two cannot disagree. `protected_from_definition` reads the
    patterns back and refuses one it cannot attribute to a network, so a hand-edited regex is a
    load-time refusal rather than a hole that only shows when someone is locked out.

    Raises:
        StateError: Whatever `protected_networks` raises for the same list.
    """
    networks = protected_networks(cidrs)
    patterns = [_v4_pattern(network) for network in networks if network.version == 4]
    if any(network.version == 6 for network in networks):
        patterns.append(r'.*:.*')
    return {'not': {'anyOf': [{'pattern': pattern} for pattern in patterns]}}


def _network_from_pattern(pattern: str) -> Any:
    """The network a generated pattern came from, or `None` when it is not one this module wrote."""
    if not pattern.startswith('^'):
        return None
    body = pattern[1:]
    if body.endswith('($|/)'):
        body, fixed = body[:-len('($|/)')], 32
    else:
        body, fixed = (body[:-2] if body.endswith('\\.') else body), None
    parts = [part for part in body.split('\\.') if part != '']
    if not 1 <= len(parts) <= 4 or any(not part.isdigit() for part in parts):
        return None
    prefix = fixed if fixed is not None else len(parts) * 8
    try:
        network = ipaddress.ip_network('.'.join(parts + ['0'] * (4 - len(parts))) + f'/{prefix}',
                                       strict=True)
    except ValueError:
        return None
    return network if _v4_pattern(network) == pattern else None


def protected_from_definition(definition: Mapping[str, Any]) -> list[Any]:
    """The protected networks one action definition enforces, read out of its own schema.

    The readable `protected_destinations` list is a description; the schema inside `parameters` is the
    enforcement. This re-derives the networks from the schema's patterns and refuses a definition where
    the two disagree, so the field a human edits can never drift from the rule that actually bites.

    Raises:
        StateError: The definition carries no protected-value schema, a pattern this module did not
            generate, or a readable list naming different networks than the patterns do.
    """
    parameters = definition.get('parameters')
    properties = parameters.get('properties') if isinstance(parameters, Mapping) else None
    fragment = properties.get('value') if isinstance(properties, Mapping) else None
    exclusion = fragment.get('not') if isinstance(fragment, Mapping) else None
    rows = exclusion.get('anyOf') if isinstance(exclusion, Mapping) else None
    listed = protected_networks(definition.get(PROTECTED_KEY) or [])
    if (not isinstance(exclusion, Mapping) or set(exclusion) != {'anyOf'}
            or not isinstance(rows, list) or not rows):
        raise StateError('An address-carrying action definition must carry a protected-value schema')
    if any(not isinstance(row, dict) or set(row) != {'pattern'}
           or not isinstance(row['pattern'], str) for row in rows):
        raise StateError('A protected-value schema must contain only generated pattern restrictions')
    patterns = [row['pattern'] for row in rows]
    if patterns.count(r'.*:.*') != int(any(network.version == 6 for network in listed)):
        raise StateError('An action definition\'s protected destinations disagree with its own schema')
    recovered: list[str] = []
    for pattern in patterns:
        if pattern == r'.*:.*':
            continue
        network = _network_from_pattern(pattern)
        if network is None:
            raise StateError(f'A protected-value pattern is not attributable to a network: {pattern}')
        recovered.append(str(network))
    if sorted(recovered) != sorted(str(network) for network in listed if network.version == 4):
        raise StateError('An action definition\'s protected destinations disagree with its own schema')
    return listed


def protected_covers(networks: Iterable[Any], address: str) -> bool:
    """Whether `address` (or prefix) lands inside, contains or overlaps a protected network. Exact.

    This is the check a *writer* would run, and it catches what a text pattern cannot: prefix overlap in
    both directions (`192.0.2.0/23` over a protected `/24`). Nothing ships that blocks, so today it is
    the proof that the schema is not the whole story — plus the oracle `validate_action_document`'s own
    tests use — rather than a second enforcement point.

    Raises:
        StateError: `address` is neither a literal address nor a prefix.
    """
    try:
        candidate: Any = (ipaddress.ip_network(address, strict=False) if '/' in str(address)
                          else ipaddress.ip_address(address))
    except ValueError:
        raise StateError('A decision value must be an address or a prefix') from None
    for network in networks:
        if candidate.version != network.version:
            continue
        if isinstance(candidate, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            if candidate in network:
                return True
        elif candidate.overlaps(network):
            return True
    return False


# ------------------------------------------------------- action definitions (LO_ACTION_POLICY)


#: The canonical-spelling rule for a decision value, and the reason it sits next to the protected
#: patterns rather than inside them: a `not`/`pattern` gate is a text gate, and `192.000.002.007` is the
#: same address as `192.0.2.7` while matching none of the protected patterns. Python's `ipaddress`
#: refuses leading-zero octets outright, so requiring the spelling `ipaddress` accepts closes the
#: evasion at the same boundary that enforces the allowlist — no second check, no new refusal word.
#: IPv4: four octets with no leading zeros, optionally one of the 0..32 prefixes. IPv6: lower-case
#: colon-hex only, so `FE80::1` cannot be a shield either (and `protected_schema` refuses every IPv6
#: value as soon as any IPv6 network is protected).
CANONICAL_VALUE = (r'^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}(?:/(?:[0-9]|[12][0-9]|3[0-2]))?$'
                   r'|^[0-9a-f][0-9a-f:]{1,43}$')

#: The parameter shape the two write actions share, minus what only one of them can mean. `type` is
#: `ban` only: threat detection engine kept CrowdSec's brute-force half, and `captcha`/`enforce_mfa` are other products'
#: decisions with other blast radii. `duration` is bounded to `1..99999` of s/m/h, so "ban forever" is
#: not a valid parameter and a mistake cannot outlive the host that made it. `reason` is required and
#: floored at 10 characters: an unexplained block is a block nobody will be able to justify in the audit
#: a month later, and the ceiling keeps `policy.py`'s own 8 KiB canonical-parameters bound unremarkable.
PARAMETERS_SCHEMA_BASE: dict[str, Any] = {
    'type': 'object',
    'additionalProperties': False,
    'properties': {
        'scope': {'enum': ['Ip', 'Range']},
        'value': {'type': 'string', 'minLength': 3, 'maxLength': 45, 'pattern': CANONICAL_VALUE},
        'type': {'const': 'ban'},
        'duration': {'type': 'string', 'pattern': r'^[1-9][0-9]{0,4}(s|m|h)$'},
        'reason': {'type': 'string', 'minLength': 10, 'maxLength': 200},
    },
}

#: What each write action must carry. A removal takes no `type` and no `duration` — there is nothing to
#: ban and no span to expire — and `additionalProperties: false` means the fields are absent from its
#: schema rather than merely unmentioned, so a proposal cannot smuggle a ban inside an unban.
ACTION_REQUIRED: dict[str, list[str]] = {
    'crowdsec-decision-apply': ['scope', 'value', 'type', 'duration', 'reason'],
    'crowdsec-decision-remove': ['scope', 'value', 'reason'],
}


def write_action_definitions(cidrs: Iterable[str] = SHIPPED_PROTECTED_SLOTS,
                             *, version: str = '1') -> dict[str, Any]:
    """The two action definitions this component needs, as a document fragment for `LO_ACTION_POLICY`.

    `crowdsec-decision-apply` creates a decision; `crowdsec-decision-remove` deletes one. Both carry the
    same protected-value schema, because a removal is a block-shaped act too: an operator who approves
    "remove the ban on the entire /0" has not approved anything, and the protected list refuses the
    over-broad prefix exactly as it refuses the protected host. The fields differ where the verbs differ
    (`ACTION_REQUIRED`).

    The fragment is merged into the operator's own policy file, never mounted alone — `LO_ACTION_POLICY`
    is one document naming every allowlisted action, and replacing it would delete the actions another
    component allowlisted.

    Returns:
        `{action name: {version, parameters, protected_destinations}}`, self-consistent by construction:
        `protected_from_definition` accepts everything this function emits, which is what
        `tests/test_crowdsec_actions.py` asserts in both directions.

    Raises:
        StateError: Whatever `protected_networks` raises for the same list.
    """
    networks = [str(network) for network in protected_networks(cidrs)]
    definitions: dict[str, Any] = {}
    for name in WRITE_ACTIONS:
        parameters = json.loads(json.dumps(PARAMETERS_SCHEMA_BASE))
        parameters['required'] = list(ACTION_REQUIRED[name])
        parameters['properties']['value'].update(protected_schema(networks))
        keep = set(ACTION_REQUIRED[name])
        parameters['properties'] = {key: value for key, value in parameters['properties'].items()
                                    if key in keep}
        definitions[name] = {'version': version, 'parameters': parameters, PROTECTED_KEY: list(networks)}
    return definitions


def validate_action_document(document: Any) -> list[str]:
    """Every reason a `LO_ACTION_POLICY` document fails this component's promises, as readable lines.

    Per write action named in `WRITE_ACTIONS`: the definition exists, its `version` is a bounded label,
    it declares a protected list that parses, and the schema in `parameters` refuses exactly those
    networks. A missing `crowdsec-*` action is *not* an error — the component is optional, and refusing
    an action nobody installed would make this check unusable on a deployment that runs without it.

    Returns:
        One line per failure, empty when the document is sound. It returns rather than raises because
        its caller's job is to tell an operator every problem with the file they just wrote, not to stop
        at the first.
    """
    if not isinstance(document, dict):
        return ['LO_ACTION_POLICY document must be a JSON object of action names']
    errors: list[str] = []
    for name in WRITE_ACTIONS:
        definition = document.get(name)
        if definition is None:
            continue
        if not isinstance(definition, dict) or not {'version', 'parameters'} <= set(definition):
            errors.append(f'{name}: an action definition must carry version and parameters')
            continue
        try:
            label(definition['version'])
        except StateError:
            errors.append(f'{name}: version must be a bounded identifier')
        try:
            protected_from_definition(definition)
        except StateError as exc:
            errors.append(f'{name}: {exc}')
    return errors


def action_request(*, retry_key: str, incident_id: str, action: str, targets: list[str],
                   scope: str, value: str, reason: str, evidence: list[str], expires_at: str,
                   duration: str = '', version: str = '1') -> dict[str, Any]:
    """Build one `propose_action` document for a CrowdSec decision, with the address spelled out.

    The address is always in `parameters` and never a bare `decision_id` the platform cannot read: a
    proposal citing only a CrowdSec row would make the protected-destination gate judge a number, and
    the human approving it would be approving bytes rather than a block. `policy.py` separately requires
    each target to be a declared resource opted into remediation, so `targets` names *where* the block
    applies and `value` names *who* is blocked — two questions, two fields, no ambiguity for either.

    Raises:
        StateError: A field is outside the shape `state.propose_action` and the shipped schema admit.
    """
    if action not in WRITE_ACTIONS:
        raise StateError('Unknown CrowdSec action')
    if scope not in ('Ip', 'Range'):
        raise StateError('CrowdSec decision scope must be Ip or Range')
    if not isinstance(targets, list) or not 1 <= len(targets) <= 20 or len(set(targets)) != len(targets):
        raise StateError('Expected distinct bounded targets')
    if not 1 <= len(evidence) <= 20:
        raise StateError('Action requires bounded incident event evidence')
    for target in targets:
        identifier(target)
    for event_id in evidence:
        identifier(event_id)
    normalised = _address_text(value, 'decision value', prefix=scope == 'Range')
    if normalised != value:
        raise StateError('A decision value must be spelled in its canonical form, not a variant of it')
    if not isinstance(reason, str) or not 10 <= len(reason) <= 200:
        raise StateError('CrowdSec decision reason must be 10..200 characters')
    if action == 'crowdsec-decision-apply':
        if not isinstance(duration, str) or not re.fullmatch(r'[1-9][0-9]{0,4}(s|m|h)', duration):
            raise StateError('CrowdSec decision duration must be 1..99999 of s, m or h')
    elif duration:
        raise StateError('A decision removal carries no duration to expire on')
    parameters: dict[str, Any] = {'scope': scope, 'value': normalised,
                                  'reason': reason}
    if action == 'crowdsec-decision-apply':
        parameters['type'] = 'ban'
        parameters['duration'] = duration
    return {'retry_key': label(retry_key), 'incident_id': identifier(incident_id),
            'action': label(action), 'version': label(version), 'targets': list(targets),
            'parameters': parameters,
            'evidence': list(evidence), 'expires_at': expires_at}


# --------------------------------------------------------------------------- command surface


def _rules_problems(document: Any) -> list[str]:
    """The rules document's failures as lines, because the two checkers answer in different shapes.

    `validate_action_document` returns one line per problem; `validate_rules` raises on the first. The
    command surface exists to be run by a human before a service starts, so the difference is adapted
    here rather than by loosening either function's contract — and the adaptation is tested, because the
    first version of this line treated a returned *mapping* of parsed rules as a list of problems and
    exited 1 on a perfectly good rules file.
    """
    try:
        validate_rules(document)
    except StateError as exc:
        return [str(exc)]
    return []


USAGE = ('usage: python -B -m local_observe.platform.crowdsec '
         '(--check-actions|--check-rules) FILE')


def main(argv: list[str] | None = None) -> int:
    """`--check-actions FILE` or `--check-rules FILE`, offline and read-only.

    This is the only caller `validate_action_document` has, and it exists because the alternative is an
    operator discovering a mis-declared protected range at the moment a block they needed is refused —
    or, worse, at the moment one they did not need is allowed. One file, at most 64 KiB, refused before
    anything else reads it. No `lo-platform` subcommand ships: `cli.py` is not this item's file, and a
    command line that minted a `human` actor from a flag would be claiming a role rather than proving
    one (the same reasoning suppression records for its own callable-only surface).

    Returns:
        `0` when the document is sound, `1` when it is not or cannot be read, `2` on a bad command line.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    kinds: dict[str, Any] = {'--check-actions': validate_action_document,
                             '--check-rules': _rules_problems}
    if len(argv) != 2 or argv[0] not in kinds:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        raw = Path(argv[1]).read_bytes()
    except OSError:
        print(f'{argv[1]}: not readable', file=sys.stderr)
        return 1
    if not raw or len(raw) > MAX_ACTION_DOCUMENT_BYTES:
        print(f'{argv[1]}: must hold between 1 and {MAX_ACTION_DOCUMENT_BYTES} bytes', file=sys.stderr)
        return 1
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        print(f'{argv[1]}: not UTF-8 JSON', file=sys.stderr)
        return 1
    try:
        errors = kinds[argv[0]](document) or []
    except StateError as exc:
        print(f'{argv[1]}: {exc}', file=sys.stderr)
        return 1
    for line in errors:
        print(line, file=sys.stderr)
    if errors:
        return 1
    print(f'{argv[1]}: ok')
    return 0


register()


if __name__ == '__main__':
    raise SystemExit(main())
