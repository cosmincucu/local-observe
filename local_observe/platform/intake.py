"""Inbound normalisation: an external alert payload becomes events this platform admits.

v0.1's `aiops/ingest` front door published whatever it received: an unknown source came back
`unnormalized=True` and still reached the bus, and an alert with no resource link got a label saying
so. The visible-degradation stance is kept; the *publish anything* stance is not, because
`platform/state.py`'s intake is stricter than v0.1's `core.events.validate` in ways an external
payload cannot satisfy by accident (`docs/CONTRACTS.md` §4): `resource_id` (or an explicit null),
`rule_id`/`rule_version`, a window of at most seven days ending no later than the instant that judged
it, and 1–20 evidence references that outlive the window.

Four rules decide everything in this module:

1. **Evidence, or coverage.** An event may reference only a sample this platform *kept* — the
   `Store.put_evidence` row that the payload itself supplied (an adapter may not synthesise an
   evidence reference to data it did not capture). A payload with nothing keepable becomes a
   `coverage` event about **the intake source**, never a verdict about the thing the alert named. That
   is the pair `detections.evaluate` emits, in the same order: coverage first, then the finding the
   coverage says is now judgeable.
2. **Linking is enrichment, never identity.** The payload's `instance`/`host` is looked up through
   `inventory/index.py`'s existing `resolve()`; a name that does not resolve lands as the admitted
   `resource_id = None` and the answer says so. No UUID is invented and none is derived from a name
   (that is v0.1's `core/identity.py`, which canonical identifier decided against).
3. **A malformed payload is refused, not degraded.** Coverage answers "this alert was well-formed and
   I cannot turn it into a statement about the watched thing"; it is not the answer to "this body is
   broken", which gets a refusal naming the position and the field. v0.1 wrapped non-object alerts and
   published them; here nothing is admitted when the envelope cannot be read, because intake opens an
   incident for any firing event and a fabricated one is worse than a lost one.
4. **Loudness and kind come from the declared rule.** Severity rides
   `vocabulary.severity('alertmanager', ...)`, whose own rows already fold Alertmanager's
   `crit`/`err`/`warn`; the `kind` cannot, because `alertmanager` deliberately declares no closed type
   space (`labels.alertname` is free text somebody typed into a route). The kind therefore comes from
   the operator's intake rules — one row per alert name, saying which kind of verdict that rule makes.
   An alert name with no row is coverage, not a guess.

No HTTP lives here. The transport is `platform/api.py`'s `/v1/intake/<source>` route, and the unit
tier never binds or connects a socket (the rule v0.1 states for its own `WebhookServer`). Every
function here is deterministic given the `now` it is handed, and reads nothing but its arguments plus
the read-only inventory index and the rules document it was given.
"""
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
import datetime as dt
import ipaddress
import json
import math
from pathlib import Path
import sqlite3
from typing import Any

from local_observe.inventory import index
from local_observe.inventory.validation import InvalidInventory, digest, timestamp, utc_text
from local_observe.log import get_logger
from . import vocabulary
from .detections import event as build_event
from .state import EVENT_KINDS, StateError, label

log = get_logger(__name__)

__all__ = ['Prepared', 'register', 'adapters', 'prepare', 'normalise', 'retry_identity',
           'validate_rules', 'load_rules', 'rules_from_environment', 'candidate_aliases',
           'alertmanager', 'RULES_ENVIRONMENT', 'MAX_ENVELOPE_ALERTS']

#: The environment variable naming the *file* of declared intake rules. Absent or blank is the off
#: switch, and off is loud: every webhook then refuses with the reason below rather than inventing a
#: rule to put in its place.
RULES_ENVIRONMENT = 'LO_INTAKE_RULES'

#: How many `alerts[]` entries one envelope may carry. `api.py`'s 64 KiB body ceiling bounds the bytes;
#: this bounds the work and the incident count one POST can cause. An envelope over it is refused
#: whole — never truncated, because a silently dropped alert is an outage the tool creates.
MAX_ENVELOPE_ALERTS = 50

#: Per-alert label and annotation ceilings, both well above what Alertmanager itself sends. A payload
#: over them is a caller that has lost the plot, not a rule an operator wrote.
MAX_LABELS = 32
MAX_ANNOTATIONS = 16
MAX_TEXT_CHARS = 256
MAX_FIELD_NAME_CHARS = 64
MAX_SAMPLE_CHARS = 32

#: How many alias candidates one alert may ask the inventory about: the raw `instance`, that value
#: without a `:port`, the same for `host`, and an address form of each. Six is the ceiling the shapes
#: above can produce, and it is what keeps a payload with many host-shaped labels from turning one
#: alert into a scan of the alias table.
MAX_ALIAS_CANDIDATES = 6

#: Rules-document bounds. The document is operator configuration, so it is bounded like one: 64 KiB on
#: disk, at most this many sources and alert names, every row refused before the first webhook is
#: served rather than at the moment an alert happens to match it.
MAX_RULES_BYTES = 65536
MAX_RULE_SOURCES = 8
MAX_RULES_PER_SOURCE = 500

#: The shortest and longest evaluation window a declared rule may claim. `MIN` is also the window used
#: for an alert with no declared rule — the shortest honest claim available ("this alert speaks about
#: the minute in which it opened"). `MAX` is `state.validate_event`'s seven-day ceiling expressed in
#: seconds, so a rule can never declare a window the state layer would go on to refuse.
MIN_WINDOW_SECONDS = 60
MAX_WINDOW_SECONDS = 86400
DEFAULT_RULE_VERSION = '1'

#: The allowance `state.validate_event` grants a clock running ahead of the instant judging an event.
#: Restated here because `state.py` keeps that number inline and exports no name for it: the two must
#: agree, or this module refuses alerts that intake would have admitted (worse) or admits alerts intake
#: goes on to refuse (a partial batch). Widening it in `state.py` must widen it here.
CLOCK_SKEW_SECONDS = 60

#: Alertmanager's "zero time" — the value its webhook sends in `endsAt` for an alert that has not
#: ended, and what a template leaves behind when a resolver never set the field.
ZERO_TIME_PREFIX = '0001-01-01'

#: The two coverage rule names this adapter owns for gaps in the *intake*, as opposed to gaps in a
#: declared rule. Both are fixed strings, never derived from a label: identity that moves when an
#: operator edits a name is the `derive_dedup_key` defect `docs/CONTRACTS.md` §4 refuses. Each holds
#: its own condition key, so neither can mask the other or a declared rule's coverage.
UNDECLARED_RULE_COVERAGE = 'alertmanager.undeclared-rule.coverage'
SEVERITY_REFUSED_COVERAGE = 'alertmanager.severity-refused.coverage'

SEVERITY_LABEL = 'severity'
ALERT_NAME_LABEL = 'alertname'
SOURCE_VOCABULARY = 'alertmanager'

_STATUS_WORDS = ('firing', 'resolved')
_RULE_FIELDS = frozenset({'rule_id', 'kind', 'rule_version', 'window_seconds', 'sample_field'})


@dataclass(frozen=True)
class Prepared:
    """One event to admit, the evidence that must be captured before it, and how linking went.

    `sample` is `None` for an event that references nothing the payload had to hand over: a
    `coverage` event's `source-heartbeat` reference is reauthorised from the platform's own receipt of
    this source, the form `detections.evaluate` and `configdrift.coverage_finding` already use.

    `link` is the inventory's answer about the instance name the payload spelled — `resolved`,
    `unknown`, `conflict`, or `not_configured`/`index_unavailable`/`no_alias` when there was nothing
    to ask. It travels in the HTTP answer because the canonical event has no field for it and must not
    gain one: an unresolved event is *admissible*, so the degradation has to be visible somewhere.
    """
    event: dict[str, Any]
    sample: dict[str, Any] | None
    link: str


Adapter = Callable[..., list[Prepared]]

# Registry keyed by the source name its webhook path names (`/v1/intake/<source>`). Filled at import
# time below: v0.1's `aiops/ingest/adapters/__init__.py` pattern kept inside one module, because with
# a single adapter there is no import cycle to break and no second file for a later card to forget.
_ADAPTERS: dict[str, Adapter] = {}


def register(source: str, adapter: Adapter) -> None:
    """Bind an adapter to its source name; a source has exactly one normaliser.

    Args:
        source: The name `/v1/intake/<source>` carries and the `source` field the events take.
        adapter: A callable taking the payload plus `now`, `index_path` and this source's rules.

    Raises:
        StateError: `source` is not a bounded identifier, or a normaliser is already registered under
            it. A second adapter for one source would make "which mapping ran?" depend on import
            order, which is how two versions of one field mapping end up live at once.
    """
    label(source)
    if source in _ADAPTERS:
        raise StateError(f'Intake adapter already registered for source {source}')
    _ADAPTERS[source] = adapter


def adapters() -> tuple[str, ...]:
    """The registered source names, sorted: what a webhook path may legitimately carry."""
    return tuple(sorted(_ADAPTERS))


def prepare(source: str, payload: Any, *, now: dt.datetime, index_path: Path | str | None = None,
            rules: Mapping[str, Any] | None = None) -> list[Prepared]:
    """Normalise one inbound payload into what to admit, in the order it must be admitted.

    This is the transport-facing entry point: the route must call `Store.put_evidence` for every
    non-null `sample` **before** the event referencing it, exactly as `detection_worker.tick` posts
    `/v1/evidence` before `/v1/events`. The samples travel beside the events instead of being stored
    here so this module stays free of the store and of every credential: the caller holds the
    producer's identity, and identity is what `put_evidence` keys its rows by.

    Args:
        source: The registered source name; also the `source` field of every event produced.
        payload: The decoded request body, spelled the way that source spells it.
        now: The instant judging this payload. Required and never defaulted: a normaliser reading its
            own clock cannot be tested at a fixed second, and determinism is what makes a re-post
            byte-identical and therefore a duplicate row rather than a second incident.
        index_path: The built inventory index to resolve instance names against, if any.
        rules: `validate_rules`' return; this source's rows are read out of it here.

    Returns:
        One `Prepared` per event, coverage before finding, in payload order.

    Raises:
        StateError: No adapter for `source`, no rules for it, or a malformed payload. Whole-envelope:
            no event of a refused payload is admitted.
    """
    label(source)
    adapter = _ADAPTERS.get(source)
    if adapter is None:
        raise StateError(f'No intake adapter is registered for source {source}; registered: '
                         f'{", ".join(adapters()) or "none"}')
    rows = rules.get(source) if isinstance(rules, Mapping) else None
    rows = dict(rows) if isinstance(rows, Mapping) else {}
    if not rows:
        raise StateError(f'No intake rules are configured for source {source}; nothing was admitted')
    return adapter(payload, now=now, index_path=index_path, rules=rows)


def normalise(source: str, payload: Any, *, now: dt.datetime, index_path: Path | str | None = None,
              rules: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    """The canonical events one payload describes, without the evidence each one needs captured first.

    The interface the contract names; `prepare` is what a transport uses, because an event whose
    sample was never stored is a dead link and this signature cannot express that. Every dict here is
    the `.event` of a `Prepared` for the same arguments — pinned by a test, so the two surfaces cannot
    drift apart.

    Raises:
        StateError: Whatever `prepare` raises for the same arguments.
    """
    return [item.event for item in prepare(source, payload, now=now, index_path=index_path, rules=rules)]


def retry_identity(built: Mapping[str, Any]) -> str:
    """The `source_event_id` for one canonical event built by `detections.event`.

    `detections.event` derives its own from `(rule_id, rule_version, resource_id, window)`, which suits
    a producer that re-*evaluates* a window — and is unusable for an inbound alert, because
    Alertmanager posts the two transitions of one condition with the same `startsAt`: a firing alert
    and its resolution can differ in `status` alone. Under the factory's identity those two events
    collide on `events UNIQUE (source, source_event_id)` with different contents, which `Store.intake`
    answers `Event retry changed contents`: the resolution is lost, the whole envelope 400s behind it,
    and the incident can never close. `status` is therefore part of the identity here and nothing else
    is added to it.

    `status` is admissible because it is one of the three words the schema admits. `fingerprint`, a
    label value or `generatorURL` are not: they would make event identity a function of mutable label
    text, which is the `derive_dedup_key` defect `docs/CONTRACTS.md` §4 refuses by name.

    Raises:
        StateError: The event is not a canonical event this function may name.
    """
    for name in ('source', 'rule_id', 'rule_version', 'status'):
        if not isinstance(built.get(name), str):
            raise StateError('Canonical event is missing a retry-identity field')
    window = built.get('window')
    if not isinstance(window, Mapping) or not {'start', 'end'} <= set(window):
        raise StateError('Canonical event carries no bounded window')
    resource_id = built.get('resource_id')
    if resource_id is not None and not isinstance(resource_id, str):
        raise StateError('Canonical resource identity must be a UUID or null')
    return digest([built['source'], built['rule_id'], built['rule_version'], resource_id,
                   window['start'], window['end'], built['status']])


def _stamp(built: dict[str, Any]) -> dict[str, Any]:
    """Set `retry_identity` on an event the factory just built, and return it.

    The one place in this package that writes a canonical field after the factory made it, and
    `retry_identity` carries the reason it is necessary. The clean home is a parameter on
    `detections.event`, which `alert conditions` owns in this wave; until that lands this edit is one line, named
    here, and pinned by the firing/resolved collision test in `tests/test_intake_alertmanager.py`.
    """
    built['source_event_id'] = retry_identity(built)
    return built


# --------------------------------------------------------------------------- rules document


def _rule_row(alert_name: str, entry: Any) -> dict[str, Any]:
    """Validate one declared rule row and return it with its defaults resolved.

    Raises:
        StateError: The row is missing `rule_id`/`kind`, names a `kind` outside
            `state.EVENT_KINDS` (a configuration file may not widen the vocabulary — the four places a
            kind moves are listed in `DEPENDENCIES.md`), declares a window outside
            `MIN_WINDOW_SECONDS`..`MAX_WINDOW_SECONDS`, or carries a field this contract does not have.
    """
    if not isinstance(alert_name, str) or not 1 <= len(alert_name) <= MAX_TEXT_CHARS:
        raise StateError('Intake rule names must be bounded strings')
    if not isinstance(entry, dict) or not {'rule_id', 'kind'} <= set(entry) or set(entry) - _RULE_FIELDS:
        raise StateError(f'Intake rule {alert_name} must name rule_id and kind, and nothing else')
    label(entry['rule_id'])
    if entry['kind'] not in EVENT_KINDS:
        raise StateError(f'Intake rule {alert_name} names a kind outside the admitted vocabulary')
    version = entry.get('rule_version', DEFAULT_RULE_VERSION)
    label(version)
    seconds = entry.get('window_seconds', MIN_WINDOW_SECONDS)
    if (isinstance(seconds, bool) or not isinstance(seconds, int)
            or not MIN_WINDOW_SECONDS <= seconds <= MAX_WINDOW_SECONDS):
        raise StateError(f'Intake rule {alert_name} must declare window_seconds as an integer '
                         f'{MIN_WINDOW_SECONDS}..{MAX_WINDOW_SECONDS}')
    field = entry.get('sample_field')
    if field is not None and (not isinstance(field, str) or not 1 <= len(field) <= MAX_FIELD_NAME_CHARS
                              or field != field.strip()):
        raise StateError(f'Intake rule {alert_name} declares an unusable sample_field')
    return {'rule_id': entry['rule_id'], 'kind': entry['kind'], 'rule_version': version,
            'window_seconds': seconds, 'sample_field': field}


def validate_rules(document: Any) -> dict[str, dict[str, Any]]:
    """Check a rules document and return `{source: {alert name: rule row}}`.

    A source with no registered adapter is refused rather than ignored: a rule that could never fire
    is a typo, and refusing it is what makes "why did my alert become coverage?" answerable from the
    file. An empty row set for a source is refused for the same reason — it is the off switch for that
    source, not a wildcard that admits everything.

    Raises:
        StateError: The document is not a bounded `{'schema_version': 1, 'sources': {...}}`, or any
            row of it is refused by `_rule_row`.
    """
    if not isinstance(document, dict) or set(document) != {'schema_version', 'sources'}:
        raise StateError('Intake rules document must hold schema_version and sources only')
    if document['schema_version'] != 1:
        raise StateError('Unsupported intake rules schema version')
    sources = document['sources']
    if not isinstance(sources, dict) or not 1 <= len(sources) <= MAX_RULE_SOURCES:
        raise StateError(f'Intake rules must declare between 1 and {MAX_RULE_SOURCES} sources')
    result: dict[str, dict[str, Any]] = {}
    for name, rows in sources.items():
        label(name)
        if name not in _ADAPTERS:
            raise StateError(f'Intake rules name a source no adapter is registered for: {name}')
        if not isinstance(rows, dict) or not 1 <= len(rows) <= MAX_RULES_PER_SOURCE:
            raise StateError(f'Intake rules for {name} must declare between 1 and {MAX_RULES_PER_SOURCE} alerts')
        result[name] = {str(key): _rule_row(str(key), value) for key, value in rows.items()}
    return result


def load_rules(path: Path | str) -> dict[str, dict[str, Any]]:
    """Read and validate the JSON file `RULES_ENVIRONMENT` names; every refusal names a field.

    The document is re-encoded after parsing so a value the JSON reader accepted but canonical JSON
    cannot express (a non-finite number, a non-string key) is refused here rather than surfacing as a
    500 from `canonical` at the first webhook.

    Raises:
        StateError: The file is unreadable, empty, oversized, not UTF-8 JSON, not expressible as
            canonical JSON, or refused by `validate_rules`.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise StateError('Intake rules file is not readable') from None
    if not raw or len(raw) > MAX_RULES_BYTES:
        raise StateError(f'Intake rules file must hold between 1 and {MAX_RULES_BYTES} bytes')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise StateError('Intake rules file is not UTF-8 JSON') from None
    result = validate_rules(document)
    try:
        json.dumps(document, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        raise StateError('Intake rules file is not expressible as canonical JSON') from None
    return result


def rules_from_environment(environment: Mapping[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """This process's intake rules, or nothing at all when the webhook is switched off.

    An unset or blank `LO_INTAKE_RULES` is the documented off switch and logs one INFO line naming the
    variable — the shape every optional producer here takes (`LO_DRIFT_CONFIG`,
    `LO_ANOMALY_CONFIG`). The difference is that off has to be loud *to the sender* too: with no rules `prepare` refuses
    every payload with a reason instead of accepting it and inventing a rule, so a misconfigured
    install cannot quietly turn an estate's alerts into nothing at all.

    Raises:
        StateError: The variable names a file that `load_rules` refuses.
    """
    environ = {} if environment is None else environment
    raw = (environ.get(RULES_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Intake webhooks are off', extra={'variable': RULES_ENVIRONMENT})
        return {}
    return load_rules(raw)


# --------------------------------------------------------------- inventory resource linking


class Links:
    """Resolve the names a payload spells against the declared index, once per payload.

    Enrichment only, and deliberately not a resolver: the lookup is `inventory/index.resolve`, handed
    every candidate at once, which answers `conflict` when the candidates disagree. An unavailable
    index leaves events unresolved rather than stopping intake — v0.1's `_link` had the same property,
    and a monitoring front door that stops intake because its inventory read failed manufactures the
    very outage it exists to report.
    """

    def __init__(self, index_path: Path | str | None) -> None:
        self._stack = ExitStack()
        self.connection: sqlite3.Connection | None = None
        self.status = 'not_configured' if index_path is None else 'index_unavailable'
        if index_path is None:
            return
        try:
            self.connection = self._stack.enter_context(index.readonly(index_path))
            self.status = 'ready'
        except (OSError, InvalidInventory, sqlite3.Error) as exc:
            log.warning('Intake resource linking is unavailable; events stay unresolved',
                        extra={'error_class': type(exc).__name__})

    def __enter__(self) -> 'Links':
        """Enter the one read-only index session a payload is linked through."""
        return self

    def __exit__(self, *exc_info: Any) -> None:
        """Close the session; the connection is read-only, so there is nothing to commit or roll back."""
        self._stack.close()

    def resolve(self, labels: Mapping[str, Any]) -> tuple[str | None, str]:
        """Return `(resource_id, link status)` for the instance/host names this alert carries."""
        if self.connection is None:
            return None, self.status
        aliases = candidate_aliases(labels)
        if not aliases:
            return None, 'no_alias'
        match = index.resolve(self.connection, aliases=aliases)
        status = str(match['status'])
        resource_id = match['resource_id'] if status == 'resolved' else None
        return (resource_id if isinstance(resource_id, str) else None), status


def _hostname_alias(value: str) -> dict[str, str] | None:
    """A hostname alias candidate, or nothing when the value could not be one.

    `inventory.validation.alias_key` lower-cases, drops a trailing dot, and refuses a value with any
    space in it or nothing left. Those refusals are applied here as *skips*, because the value came
    from a payload, and a payload is not obliged to name a host.
    """
    folded = value.strip().rstrip('.').lower()
    if not folded or any(character.isspace() for character in folded):
        return None
    return {'type': 'hostname', 'value': folded}


def _ip_alias(value: str) -> dict[str, str] | None:
    """An `ip` alias candidate, or nothing when the text is not an address.

    Probed here rather than left to `alias_key` to raise, because an address-shaped `instance` is
    ordinary and a raise would refuse an entire envelope over one candidate.
    """
    try:
        return {'type': 'ip', 'value': str(ipaddress.ip_address(value.strip()))}
    except ValueError:
        return None


def candidate_aliases(labels: Mapping[str, Any]) -> list[dict[str, str]]:
    """The alias candidates for `instance`/`host`, in the order the index should be asked.

    `instance` is often `host:9100`, so the bare name is offered beside the raw value, and an
    address-shaped value is offered as an `ip` alias. All of them go into the *one* existing
    `resolve()` call: asking rather than picking a first match is the point, because when two declared
    resources claim these names the answer is `conflict` and the event stays unresolved — a visible
    inventory problem — while a candidate chosen by order would be an identity invented here.
    """
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(alias: dict[str, str] | None) -> None:
        if alias is None or len(candidates) >= MAX_ALIAS_CANDIDATES:
            return
        key = (alias['type'], alias['value'])
        if key not in seen:
            seen.add(key)
            candidates.append(alias)

    for name in ('instance', 'host'):
        value = labels.get(name)
        if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT_CHARS:
            continue
        add(_hostname_alias(value))
        head, separator, port = value.rpartition(':')
        if separator and head and port.isdigit():
            add(_hostname_alias(head))
            bare = _hostname_alias(head)
            add(_ip_alias(bare['value']) if bare else None)
        else:
            add(_ip_alias(value))
    return candidates


# ---------------------------------------------------------------------- Alertmanager adapter


def _string_map(value: Any, field: str, maximum: int, position: int) -> dict[str, str]:
    """A source's label or annotation object: bounded, string-to-string, and refused whole.

    Absent reads as `{}` (Alertmanager sends both keys, and an alert without them is the
    undeclared-rule case below, not a crash). A non-string *value* is refused rather than stringified
    the way v0.1 did it: `str(None)` writing the four letters `None` into a comparison is how an
    absent field starts looking like a value somebody chose.
    """
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > maximum:
        raise StateError(f'Alertmanager alert {position} carries an unusable {field} object')
    out: dict[str, str] = {}
    for key, item in value.items():
        if (not isinstance(key, str) or not isinstance(item, str)
                or not 1 <= len(key) <= MAX_TEXT_CHARS or len(item) > MAX_TEXT_CHARS):
            raise StateError(f'Alertmanager alert {position} carries an unbounded {field} entry')
        out[key] = item
    return out


def _status(value: Any, position: int) -> str:
    """`firing` or `resolved`, and nothing else; v0.1's silent default to `firing` is gone.

    Neither word is a refusal of the operator's intent: `resolved` must land as `status='resolved'` on
    the event (the field this repo already has), which is what closes the incident in
    `Store.intake` — v0.1 recorded the transition as a `labels['status']` string instead, so nothing
    downstream could act on it.

    `state.validate_event` also admits `unknown`, and that word is deliberately not available to an
    inbound payload here: `Store.intake` reads it as "touch the condition, change nothing", so mapping
    garbage to it would advance a condition's watermark on a verdict nobody made.
    """
    if isinstance(value, str) and value.strip().lower() in _STATUS_WORDS:
        return value.strip().lower()
    raise StateError(f'Alertmanager alert {position} carries a status that is not firing or resolved')


def _moment(value: Any, field: str, position: int) -> dt.datetime | None:
    """One timestamp field, with Alertmanager's zero time read as *absent* and never as year 1.

    The `0001-01-01T00:00:00Z` value is what Alertmanager sends in `endsAt` for an alert that has not
    ended. v0.1 special-cased it by prefix and moved on; here it can only mean "no instant", because
    taking it literally would produce a window of ~2,000 years (refused by the seven-day bound) and, on
    a resolution, would close an incident at an instant no instrument ever read.

    Raises:
        StateError: The field holds text that is not a timezone-aware ISO instant.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise StateError(f'Alertmanager alert {position} carries an unusable {field}')
    if value.strip().startswith(ZERO_TIME_PREFIX):
        return None
    try:
        return timestamp(value)
    except InvalidInventory:
        raise StateError(f'Alertmanager alert {position} carries an unparseable {field}') from None


def _window(status: str, starts_at: dt.datetime, ends_at: dt.datetime | None, seconds: int,
            now: dt.datetime, position: int) -> tuple[dict[str, str], str]:
    """The window this alert is about, and the instant it was observed at.

    Both come from the payload alone — `now` is used only to refuse — because a re-post must reproduce
    the same bytes to fold into the row `Store.intake` already holds, and any window that slid forward
    with the clock would turn every Alertmanager repeat into a fresh incident.

    * firing: `[startsAt, startsAt + window_seconds]`. `endsAt` is unusable: for a firing alert
      Alertmanager sends the *scheduled* end of the current active period, which is in the future, and
      `state.validate_event` refuses a window ending more than a minute ahead of the instant judging it.
      The declared window is the interval the upstream rule needed the condition to hold for
      (Prometheus' `for:`), so an alert that has not yet completed its own window is refused rather
      than admitted with a window this process invented.
    * resolved: `[max(startsAt, endsAt - window_seconds), endsAt]` — the declared window, never claimed
      to have begun before the condition did. Taking the last `window_seconds` rather than the whole
      active period is what lets an incident older than the seven-day bound close at all, and it is
      honest: a resolution is a verdict about the moment the condition cleared, and that moment is
      `endsAt`. An alert that started and ended in the same instant (Prometheus permits `for: 0s`) gets
      the whole declared window ending at that instant, because a window must have a length.

    Raises:
        StateError: A future instant, a resolution whose instant the payload never carried (the zero
            time, or no `endsAt`), or a resolution that ended before it began. Each is refused rather
            than guessed — closing an incident at a watermark no instrument read is the false recovery
            this repository audits for.
    """
    limit = now + dt.timedelta(seconds=CLOCK_SKEW_SECONDS)
    if starts_at > limit:
        raise StateError(f'Alertmanager alert {position} carries a future observed_at')
    if status == 'firing':
        end = starts_at + dt.timedelta(seconds=seconds)
        if end > limit:
            raise StateError(f'Alertmanager alert {position} has not completed its declared evaluation window')
        return {'start': utc_text(starts_at), 'end': utc_text(end)}, utc_text(starts_at)
    if ends_at is None:
        raise StateError(f'Alertmanager alert {position} is resolved but carries no usable endsAt')
    if ends_at > limit:
        raise StateError(f'Alertmanager alert {position} carries a future observed_at')
    if ends_at < starts_at:
        raise StateError(f'Alertmanager alert {position} is resolved before it started')
    start = max(starts_at, ends_at - dt.timedelta(seconds=seconds))
    if start >= ends_at:
        start = ends_at - dt.timedelta(seconds=seconds)
    return {'start': utc_text(start), 'end': utc_text(ends_at)}, utc_text(ends_at)


def _sample_value(raw: str) -> int | float | bool | None:
    """A storable value out of the payload's own text, or `None` when it is not one.

    `Store.put_evidence` keeps a boolean or a number and nothing else, which is the whole shape of what
    an inbound alert may contribute as evidence: a number is read as a float, `true`/`false` in any
    case as a boolean, and everything else — including `nan`, `inf`, empty, and a 400-character
    template string — as nothing. Nothing becomes coverage, which is the honest answer; a placeholder
    row would be the synthesised reference §6 forbids.
    """
    text = raw.strip()
    if not text or len(text) > MAX_SAMPLE_CHARS:
        return None
    folded = text.lower()
    if folded in ('true', 'false'):
        return folded == 'true'
    try:
        number = float(text)
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def _name_hint(alert_name: str) -> str:
    """A loggable, bounded hint of an alert name that no event may ever carry.

    Lower-cased, every character outside `[a-z0-9]` folded to `.` with runs collapsed, capped at 64.
    Used only in the WARNING line, so an operator can find which of their rules to declare. It is not
    an identifier and not a condition: renaming the upstream rule changes a log line, never an incident.
    """
    out: list[str] = []
    for character in alert_name.lower():
        if character.isalnum():
            out.append(character)
        elif not out or out[-1] != '.':
            out.append('.')
    return ''.join(out)[:64].strip('.') or 'unnamed'


def _source_coverage(rule_id: str, resource_id: str | None, window: Mapping[str, str], status: str,
                     link: str) -> Prepared:
    """A statement about this intake source, in the shape `detections.evaluate` already uses.

    `source-heartbeat` with the source as its watched rule references nothing the payload had to
    carry: the platform's own receipt of this source *is* the evidence, which is why this form is legal
    where a captured sample would not be. The rule id names the gap (`undeclared-rule`,
    `severity-refused`), so two different gaps never share a condition key and neither can mask the
    other or a declared rule's own coverage.
    """
    built = build_event(SOURCE_VOCABULARY, resource_id, rule_id, 'coverage', status, dict(window),
                        {'rule_id': SOURCE_VOCABULARY}, query_type='source-heartbeat',
                        version=DEFAULT_RULE_VERSION)
    return Prepared(_stamp(built), None, link)


def alertmanager(payload: Any, *, now: dt.datetime, index_path: Path | str | None = None,
                 rules: Mapping[str, Any] | None = None) -> list[Prepared]:
    """Map one Alertmanager webhook envelope onto canonical events, one entry of `alerts[]` each.

    Registered under `alertmanager`; `prepare` hands over the rules already narrowed to this source.
    The envelope's own `status`, `groupKey`, `receiver`, `commonLabels` and `externalURL` are not read:
    the per-alert `status` is the truth of one condition, and a group is a delivery artefact. The only
    fields taken from an alert are `status`, `startsAt`, `endsAt`, `labels.severity`,
    `labels.alertname`, `labels.instance`/`labels.host` and the one annotation the rule declares as its
    sample. `fingerprint` is read by nobody: it is a hash of the label set, so an identity built from
    it moves every time somebody edits a label.

    Raises:
        StateError: The envelope is not an object, has no `alerts` list, is empty, carries more than
            `MAX_ENVELOPE_ALERTS` entries, or any alert of it is malformed. Nothing is admitted.
    """
    rows = dict(rules) if isinstance(rules, Mapping) else {}
    if not rows:
        raise StateError(f'No intake rules are configured for source {SOURCE_VOCABULARY}; nothing was admitted')
    if not isinstance(payload, dict):
        raise StateError('Alertmanager payload must be a JSON object')
    alerts = payload.get('alerts')
    if not isinstance(alerts, list):
        raise StateError('Alertmanager payload must carry an alerts list')
    if not 1 <= len(alerts) <= MAX_ENVELOPE_ALERTS:
        raise StateError(f'Alertmanager envelope must carry between 1 and {MAX_ENVELOPE_ALERTS} alerts')
    with Links(index_path) as links:
        produced: list[Prepared] = []
        for position, item in enumerate(alerts):
            produced.extend(_alert(item, position, rows=rows, now=now, links=links))
        return produced


def _alert(alert: Any, position: int, *, rows: Mapping[str, Mapping[str, Any]], now: dt.datetime,
           links: Links) -> list[Prepared]:
    """The events one `alerts[]` entry produces: a verdict plus its coverage, or coverage alone.

    Which of the two, per alert, is decided by one question — did this payload carry a sample this
    platform can keep? Yes: coverage `resolved` (the signal is judgeable) then the verdict, which is
    the pair `detections.evaluate` emits. No: coverage `firing` about the intake source or the declared
    rule, and the underlying condition is never opened.

    The one asymmetry, and it is deliberate: a *resolution* with no sample still files its verdict.
    Refusing it would strand the incident open forever — and a resolution adds no claim about the
    world beyond "this condition ended", which is a fact about the alert that arrived, evidenced by
    `source-heartbeat`. Opening a new condition is where evidence is required, not closing one.
    """
    if not isinstance(alert, dict):
        raise StateError(f'Alertmanager alert {position} is not an object')
    labels = _string_map(alert.get('labels'), 'labels', MAX_LABELS, position)
    annotations = _string_map(alert.get('annotations'), 'annotations', MAX_ANNOTATIONS, position)
    status = _status(alert.get('status'), position)
    starts_at = _moment(alert.get('startsAt'), 'startsAt', position)
    if starts_at is None:
        raise StateError(f'Alertmanager alert {position} carries no usable startsAt')
    ends_at = _moment(alert.get('endsAt'), 'endsAt', position)
    alert_name = labels.get(ALERT_NAME_LABEL)
    row = rows.get(alert_name) if isinstance(alert_name, str) else None
    seconds = row['window_seconds'] if row else MIN_WINDOW_SECONDS
    window, observed_at = _window(status, starts_at, ends_at, seconds, now, position)
    resource_id, link = links.resolve(labels)

    if row is None:
        log.warning('Intake alert has no declared rule; filing coverage about the intake source',
                    extra={'source': SOURCE_VOCABULARY, 'rule_id': UNDECLARED_RULE_COVERAGE,
                           'alert': position, 'name_hint': _name_hint(alert_name or '')})
        return [_source_coverage(UNDECLARED_RULE_COVERAGE, resource_id, window, 'firing', link)]
    if status == 'firing':
        return _firing(row, labels, annotations, resource_id, window, observed_at, position, link)
    return _recovering(row, annotations, resource_id, window, observed_at, link)


def _finding_evidence(row: Mapping[str, Any], annotations: Mapping[str, str], resource_id: str | None,
                      window: Mapping[str, str], observed_at: str) -> tuple[dict[str, Any] | None, str,
                                                                            dict[str, str]]:
    """`(sample, query_type, parameters)` for one verdict: the sample the payload carried, or the heartbeat.

    A captured sample is referenced as `observed-snapshot`, never `metric-threshold`: this process did
    not compare a number to a limit, the upstream rule did, and `metric-threshold` would claim a
    judgement the intake path never made. `sample_id` is derived from the fields that identify the
    reading — rule identity, resource, window, the instant it was taken at, and the value — so the
    same alert re-posted names the same row and `put_evidence` folds it instead of writing a second
    one. The instant is in the name because it is in the row: a firing alert and its resolution can
    describe one window and carry different readings, and `put_evidence` refuses an existing row whose
    contents changed, which without the instant would refuse the *resolution* before its event was ever
    seen (that refusal is `Evidence retry changed contents`, and it arrives as a 400 conflict).
    """
    field = row.get('sample_field')
    raw = annotations.get(field) if isinstance(field, str) else None
    value = _sample_value(raw) if isinstance(raw, str) else None
    if value is None:
        return None, 'source-heartbeat', {'rule_id': row['rule_id']}
    sample_id = digest([SOURCE_VOCABULARY, row['rule_id'], row['rule_version'], resource_id,
                        window['start'], window['end'], observed_at, value])
    sample = {'sample_id': sample_id, 'observed_at': observed_at, 'ok': True, 'value': value}
    return sample, 'observed-snapshot', {'rule_id': row['rule_id'], 'sample_id': sample_id}


def _recovering(row: Mapping[str, Any], annotations: Mapping[str, str], resource_id: str | None,
                window: Mapping[str, str], observed_at: str, link: str) -> list[Prepared]:
    """Coverage resolved, then the condition closing. No severity is passed: see the docstring.

    A recovery carries no loudness of its own. `docs/CONTRACTS.md` §4.1 is explicit that the mapped
    word describes the *firing* verdict and the factory's `info` is what a resolved event takes, so a
    label an operator typed for how bad a failure was cannot also name how bad its end was. Skipping
    the crosswalk here also means a rule whose severity label became unmappable can still be closed —
    a stuck incident is the worse failure.
    """
    sample, query_type, parameters = _finding_evidence(row, annotations, resource_id, window, observed_at)
    coverage = build_event(SOURCE_VOCABULARY, resource_id, row['rule_id'] + '.coverage', 'coverage',
                           'resolved', dict(window), {'rule_id': row['rule_id']},
                           query_type='source-heartbeat', version=row['rule_version'])
    finding = build_event(SOURCE_VOCABULARY, resource_id, row['rule_id'], row['kind'], 'resolved',
                          dict(window), parameters, query_type=query_type,
                          version=row['rule_version'], observed_at=observed_at)
    return [Prepared(_stamp(coverage), None, link), Prepared(_stamp(finding), sample, link)]


def _firing(row: Mapping[str, Any], labels: Mapping[str, str], annotations: Mapping[str, str],
            resource_id: str | None, window: Mapping[str, str], observed_at: str, position: int,
            link: str) -> list[Prepared]:
    """A firing alert: the verdict its sample licenses, or coverage about what the sample was not.

    Severity is the only thing the payload may say about loudness, and only through the crosswalk:
    `alertmanager`'s rows in `vocabulary.SEVERITY_CROSSWALK` already fold `crit`/`err`/`warn` into the
    long forms, and its `none`/`unknown` refusals are what turn "nobody set the severity label" into
    coverage about the ingest path instead of a guessed rung.
    """
    try:
        severity = vocabulary.severity(SOURCE_VOCABULARY, labels.get(SEVERITY_LABEL))
    except vocabulary.VocabularyError:
        log.warning('Intake severity is refused by the crosswalk; filing coverage about the intake source',
                    extra={'source': SOURCE_VOCABULARY, 'rule_id': SEVERITY_REFUSED_COVERAGE,
                           'alert': position, 'error_class': vocabulary.VocabularyError.__name__})
        return [_source_coverage(SEVERITY_REFUSED_COVERAGE, resource_id, window, 'firing', link)]
    sample, query_type, parameters = _finding_evidence(row, annotations, resource_id, window, observed_at)
    if sample is None:
        # No verdict, and no incident: opening one would need evidence this payload did not bring.
        log.warning('Intake alert carried no keepable sample; filing coverage instead of a verdict',
                    extra={'source': SOURCE_VOCABULARY, 'rule_id': row['rule_id'] + '.coverage',
                           'alert': position})
        coverage = build_event(SOURCE_VOCABULARY, resource_id, row['rule_id'] + '.coverage', 'coverage',
                               'firing', dict(window), {'rule_id': row['rule_id']},
                               query_type='source-heartbeat', version=row['rule_version'])
        return [Prepared(_stamp(coverage), None, link)]
    coverage = build_event(SOURCE_VOCABULARY, resource_id, row['rule_id'] + '.coverage', 'coverage',
                           'resolved', dict(window), {'rule_id': row['rule_id']},
                           query_type='source-heartbeat', version=row['rule_version'])
    finding = build_event(SOURCE_VOCABULARY, resource_id, row['rule_id'], row['kind'], 'firing',
                          dict(window), parameters, query_type=query_type, observed_at=observed_at,
                          version=row['rule_version'], severity=severity)
    return [Prepared(_stamp(coverage), None, link), Prepared(_stamp(finding), sample, link)]


register(SOURCE_VOCABULARY, alertmanager)
