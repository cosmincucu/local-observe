"""The one severity/`kind` crosswalk: every producer cites it, none spells its own vocabulary.

A source outside this repository arrives with words of its own — v0.1's `core.events` carries five
severities (`critical`, `error`, `warning`, `info`, `unknown`) and a free-form `type` string; a
Sigma rule carries a `level:`; Alertmanager carries a `severity` label somebody typed into a route.
This repo admits three severities (`info`, `warning`, `critical`) and six `kind`s, and intake refuses
anything else (`state.validate_event`). The step between the two is lossy, so it is decided once,
here, as tables — before any producer exists to contradict it. A card that invents a local mapping
has written a vocabulary, which is the defect this module exists to prevent.

Three tables, deliberately separate, because they answer different questions:

* `SEVERITY_CROSSWALK` — how loud. Keyed **(source, word)**, never by value alone: the same upstream
  word must not be `critical` in one producer and `warning` in another, and ladders differ in length,
  so only a per-source row can say which rung a word sits on.
* `TYPE_CROSSWALK` — what kind of verdict, and which durable condition it belongs to.
* `REFUSALS` — the words deliberately given no home, each with the one-line reason. A refusal is the
  crosswalk's answer, not a gap in it: a value with no row raises, naming the source and the word.

There is no `unknown` severity here and no default. `state.validate_event` admits no fourth severity,
so any fallback would be a silent downgrade of a verdict somebody measured; loudness can only be
raised by editing a row in this file, in a diff, with a reason.

Where an unmapped upstream value goes instead — the pattern `detections.evaluate` already uses, and
the answer for v0.1's `unknown` severity: the event that could not be classified becomes a `coverage`
event *about the source* ("the signal I need is not arriving / a payload no adapter claimed"), never
a fabricated severity about the thing being watched. Coverage says what is actually known.

`dedup_key` has no home here, deliberately. v0.1's `core.events.derive_dedup_key` hashes
`source + resource_ref + type + sorted(labels)` into a name, which makes dedup identity a function of
mutable label text: add one label to a rule and every past incident becomes a different event. This
repository's identity for an event is instead two durable pairs — `events UNIQUE (source,
source_event_id)` (retry identity; `detections.event` derives `source_event_id` from rule, version,
resource and window, so a replayed evaluation is one row) and `conditions (key, watermark, status,
incident_id)` where `key` digests `(source, rule_id, rule_version, resource_id, condition)` — which is
what groups verdicts into one incident. Both live in `platform/state.py`; `suppression`'s suppression builds
on them. Do not re-derive a name-based key here.
"""
from dataclasses import dataclass
from typing import Any

__all__ = ['VocabularyError', 'SourceVocabulary', 'SOURCE_VOCABULARIES', 'ADMITTED_SEVERITIES',
           'SEVERITY_CROSSWALK', 'TYPE_CROSSWALK', 'REFUSALS', 'severity', 'classify',
           'declared_severities', 'declared_types', 'refusals', 'v01_type']

# The three severities `state.validate_event` admits, repeated here only so a reader of this file can
# see the target of every row without opening state.py. `tests/test_event_vocabulary.py` pins the
# crosswalk against state.py itself, so this constant cannot drift silently.
ADMITTED_SEVERITIES = ('info', 'warning', 'critical')

# Characters allowed to appear in a word echoed back inside a refusal sentence. Anything else becomes
# `?`, because `api.py` puts the raised sentence into an error body (`detail: str(exc)`) and no value
# read from a request may be echoed there.
_ECHO_SAFE = frozenset('abcdefghijklmnopqrstuvwxyz0123456789_.:-')


@dataclass(frozen=True)
class SourceVocabulary:
    """What one inbound source is, and the words it itself spells.

    `severities` is the source's own ladder, loudest first, including any word in `REFUSALS` — it is
    the declaration that lets a refusal tell "this source spells that word and we decided not to map
    it" apart from "this source has never spelled that word". `closed_types` says whether the
    source's `type` space is a set that can be enumerated here at all; when it is not, the kind must
    come from the rule that judged the sample and `note` says who owes it.
    """
    name: str
    plane: str
    severities: tuple[str, ...]
    closed_types: bool
    note: str


SOURCE_VOCABULARIES: dict[str, SourceVocabulary] = {
    'core-events-v1': SourceVocabulary(
        name='core-events-v1',
        plane='v0.1 `core.events.Event`, the wire form every v0.1 emitter uses (33 product files '
              'import it); its `type` is a dotted `<package>.<name>` string chosen by the emitting package',
        severities=('critical', 'error', 'warning', 'info', 'unknown'),
        closed_types=True,
        note='unmapped types are refused; add a reviewed vocabulary entry when integrating a new producer'),
    'alertmanager': SourceVocabulary(
        name='alertmanager',
        plane='Alertmanager webhook alerts, as v0.1 `aiops/ingest/adapters/alertmanager.py` mapped '
              'them: `labels.severity` lower-cased with `crit`/`err`/`warn` folded in, and `type` '
              'taken from `labels.alertname`',
        severities=('critical', 'crit', 'error', 'err', 'warning', 'warn', 'info', 'none', 'unknown'),
        closed_types=False,
        note='`labels.alertname` is free text an operator typed into a route; no receiver may infer a '
             'kind from it. The event intake and condition evaluation derive the kind from the producing rule; '
             'this vocabulary supplies only the severity'),
    'gatus': SourceVocabulary(
        name='gatus',
        plane='Gatus endpoint results — the only fields this repo reads are `results[].success` (a '
              'bool) and `results[].timestamp`, per `detections.gatus_sample`',
        severities=(),
        closed_types=True,
        note='a Gatus result is a boolean and carries no severity of its own, so severity comes from '
             'the verdict through `detections.event` (firing is `warning`, resolved is `info`); a '
             'producer that names one here is inventing loudness'),
    'healthchecks': SourceVocabulary(
        name='healthchecks',
        plane='Healthchecks-style check-in monitoring — the semantics v0.1 `heartbeat/` adopted: a '
              'monitor expected to ping on a schedule, with a grace period and a max run duration',
        severities=(),
        closed_types=True,
        note='a check-in status is a verdict, not a severity; v0.1 emitted `error`/`warning` words '
             'from its sweeper and those ride the `core-events-v1` severities, not this source'),
    'sigma': SourceVocabulary(
        name='sigma',
        plane='Sigma rules compiled by `platform/sigma_compile.py` and executed by '
              '`platform/sigma_runner.py`; their own `level:` field plus the two events the runner '
              'emits (a finding and a source-coverage event)',
        severities=('critical', 'high', 'medium', 'low', 'informational'),
        closed_types=True,
        note='a matched rule produces a security event; set the rule level explicitly when '
             'requiring a severity other than the event factory default'),
    'crowdsec': SourceVocabulary(
        name='crowdsec',
        plane="CrowdSec alerts from its brute-force scenarios (crowdsec). A decision is read state and "
              "a block is an approved action, so neither is an event here",
        severities=(),
        closed_types=True,
        note='CrowdSec alerts are named by scenario, an open space; the alert channel is a single '
             'declared condition (`crowdsec.alert`) and the scenario belongs in the evidence, so no '
             'scenario name can widen the vocabulary'),
    'signoz': SourceVocabulary(
        name='signoz',
        plane='SigNoz/ClickHouse log severity tokens (`SeverityText`) carried on a copy of telemetry — '
              'the shape security store\'s short-TTL log copy has — never a verdict of its own',
        severities=('fatal', 'error', 'warn', 'warning', 'info', 'debug', 'trace', 'unspecified',
                    'unknown'),
        closed_types=False,
        note='SigNoz is the store, not a detector: a verdict over its data names the rule that judged '
             'it (store facade reads, alert conditions judges), so this source contributes a severity word only when '
             'one is being carried on someone else\'s event'),
}

# (source vocabulary, the source's own word) -> this repo's severity. Case and surrounding space carry
# no meaning in any of these vocabularies — Alertmanager labels are operator-typed and SigNoz stores
# `SeverityText` upper-cased — so lookup folds both; see `_fold`.
SEVERITY_CROSSWALK: dict[tuple[str, str], str] = {
    # v0.1's five collapse to three. Its ladder above `info` is critical > error > warning, and only
    # the top rung keeps `critical`: `anomaly.severity_for` reserves `critical` for a point another
    # `k` scaled-MADs beyond the band edge, so a rung that merely means "this is broken" cannot take
    # the same word without making every ordinary finding as loud as a measured escalation. `error`
    # therefore lands beside `warning`, which is exactly what the merged producers already call a
    # firing verdict (detections.event, sigma_runner, anomaly) — v0.1's `error` and this repo's
    # `warning` are the same statement in two dialects, not two levels.
    ('core-events-v1', 'critical'): 'critical',
    ('core-events-v1', 'error'): 'warning',
    ('core-events-v1', 'warning'): 'warning',
    ('core-events-v1', 'info'): 'info',
    # The same ladder read through the label Alertmanager routes on, including the three spellings
    # v0.1's adapter folded. `crit`/`err`/`warn` are the operator-typed short forms, so they answer
    # exactly as their long form does.
    ('alertmanager', 'critical'): 'critical',
    ('alertmanager', 'crit'): 'critical',
    ('alertmanager', 'error'): 'warning',
    ('alertmanager', 'err'): 'warning',
    ('alertmanager', 'warning'): 'warning',
    ('alertmanager', 'warn'): 'warning',
    ('alertmanager', 'info'): 'info',
    # Sigma's five rungs onto three: its own rubric puts `informational` as background noise, so it
    # is the only rung that becomes `info`, and collapsing the middle three onto `warning` never
    # quieter than what the merged Sigma runner already files.
    ('sigma', 'critical'): 'critical',
    ('sigma', 'high'): 'warning',
    ('sigma', 'medium'): 'warning',
    ('sigma', 'low'): 'warning',
    ('sigma', 'informational'): 'info',
    # OTel log tokens: `fatal` is the source's top rung and so may name `critical`; everything from
    # `error` down is a statement that needs acting on or noting, and the levels below `info` are
    # context nobody pages about.
    ('signoz', 'fatal'): 'critical',
    ('signoz', 'error'): 'warning',
    ('signoz', 'warn'): 'warning',
    ('signoz', 'warning'): 'warning',
    ('signoz', 'info'): 'info',
    ('signoz', 'debug'): 'info',
    ('signoz', 'trace'): 'info',
}

# (source vocabulary, type word) -> (kind, condition). `kind` says what produced the verdict and
# never how loud it is; `condition` is the durable condition identity, which the emitting producer
# passes as its `rule_id` — `detections.event` sets `condition = rule_id` and offers no other door.
#
# The boundary that decides `availability` against `coverage`, and the one every row below applies:
# a test that RAN and failed is `availability`; a test that could not run, or a signal that never
# arrived, is `coverage`. Consequence of the same rule: v0.1's `heartbeat.missed_checkin` is
# `coverage`, because a job that did not report is exactly the stale/absent input
# `detections.evaluate` refuses to read as a verdict about the job.
TYPE_CROSSWALK: dict[tuple[str, str], tuple[str, str]] = {
    # --- v0.1 core.events types, one row per type literal the v0.1 tree emits ---
    ('core-events-v1', 'anomaly.detected'): ('anomaly', 'anomaly.detected'),
    ('core-events-v1', 'config.changed'): ('drift', 'config.changed'),
    ('core-events-v1', 'collector.poll_failed'): ('coverage', 'collector.poll_failed'),
    ('core-events-v1', 'heartbeat.missed_checkin'): ('coverage', 'heartbeat.missed_checkin'),
    ('core-events-v1', 'heartbeat.ran_too_long'): ('threshold', 'heartbeat.ran_too_long'),
    ('core-events-v1', 'probe.check_failed'): ('availability', 'probe.check_failed'),
    ('core-events-v1', 'probe.test_refused'): ('coverage', 'probe.test_refused'),
    ('core-events-v1', 'probe.runner_error'): ('coverage', 'probe.runner_error'),
    ('core-events-v1', 'rum.cwv_spike'): ('threshold', 'rum.cwv_spike'),
    ('core-events-v1', 'slo.fast_burn'): ('threshold', 'slo.fast_burn'),
    ('core-events-v1', 'synthetics.api_chain.check_failed'): ('availability', 'synthetics.api_chain.check_failed'),
    ('core-events-v1', 'synthetics.api_chain.transport_error'): ('coverage', 'synthetics.api_chain.transport_error'),
    ('core-events-v1', 'synthetics.browser.journey_failed'): ('availability', 'synthetics.browser.journey_failed'),
    ('core-events-v1', 'synthetics.browser.engine_error'): ('coverage', 'synthetics.browser.engine_error'),
    ('core-events-v1', 'synthetics.browser.unavailable'): ('coverage', 'synthetics.browser.unavailable'),
    ('core-events-v1', 'synthetics.dns.check_failed'): ('availability', 'synthetics.dns.check_failed'),
    ('core-events-v1', 'synthetics.dns.resolver_error'): ('coverage', 'synthetics.dns.resolver_error'),
    ('core-events-v1', 'synthetics.http.check_failed'): ('availability', 'synthetics.http.check_failed'),
    ('core-events-v1', 'synthetics.http.transport_error'): ('coverage', 'synthetics.http.transport_error'),
    ('core-events-v1', 'synthetics.tls.check_failed'): ('availability', 'synthetics.tls.check_failed'),
    ('core-events-v1', 'synthetics.tls.fetch_error'): ('coverage', 'synthetics.tls.fetch_error'),
    # A certificate is not down, it is a number past a limit: `expiry` is a threshold verdict with a
    # days-left value behind it, which is why it must not ride `availability` and read as an outage.
    ('core-events-v1', 'synthetics.tls.expiry'): ('threshold', 'synthetics.tls.expiry'),
    # The two types `core/events.py` itself emits. Both mean "an inbound payload was not understood",
    # which is a fact about the ingest path, so both are `coverage`; and because neither carries a
    # package prefix, its condition takes one (`core.`) — a condition that bare would collide with
    # anything a later rule invents.
    ('core-events-v1', 'core.unnormalized'): ('coverage', 'core.unnormalized'),
    ('core-events-v1', 'core.webhook'): ('coverage', 'core.webhook'),
    # --- Sigma: the two events sigma_runner already writes ---
    ('sigma', 'finding'): ('security', 'sigma.finding'),
    ('sigma', 'coverage'): ('coverage', 'sigma.coverage'),
    # --- Gatus: a result that came back, and the absence of one ---
    ('gatus', 'result'): ('availability', 'gatus.result'),
    ('gatus', 'coverage'): ('coverage', 'gatus.coverage'),
    # --- Healthchecks-style check-ins: every status of a monitor is a statement about the signal ---
    # Reviewer ruling 2026-09-08 (job observe standard already stamps the missed check-in as availability with
    # rule_id 'deadman-checkin'): a check-in that is late or down says the JOB did not run or finish,
    # so it is availability of the watched job; up/new/started/finished/paused are statements about
    # the signal and stay coverage.
    ('healthchecks', 'up'): ('coverage', 'healthchecks.check-in'),
    ('healthchecks', 'late'): ('availability', 'healthchecks.check-in'),
    ('healthchecks', 'down'): ('availability', 'healthchecks.check-in'),
    ('healthchecks', 'new'): ('coverage', 'healthchecks.check-in'),
    ('healthchecks', 'started'): ('coverage', 'healthchecks.check-in'),
    ('healthchecks', 'finished'): ('coverage', 'healthchecks.check-in'),
    ('healthchecks', 'paused'): ('coverage', 'healthchecks.paused'),
    # --- CrowdSec: the alert channel only (decisions are read state, blocks are approved actions) ---
    ('crowdsec', 'alert'): ('security', 'crowdsec.alert'),
    ('crowdsec', 'coverage'): ('coverage', 'crowdsec.coverage'),
}

# Words an admitted source spells that get no home here, each with its reason in one line — a refusal
# is part of the contract, so it is written down rather than inferred from absence. Keyed
# (source vocabulary, folded word); it covers both severities and types, and both lookups read it.
REFUSALS: dict[tuple[str, str], str] = {
    ('core-events-v1', 'unknown'): 'v0.1 sets this when no adapter claimed the payload, so it names a '
                                   'missing adapter and not a state of the monitored world: file a '
                                   'coverage event about that source and keep the raw payload where '
                                   'the normaliser can show what went unnormalised',
    ('core-events-v1', 'alert.fired'): 'names a transition of an alerting condition, not a verdict; '
                                       'the kind belongs to the condition (absence, static tier or '
                                       'learned band) and the transition belongs in `status` — so '
                                       'alert conditions classifies per condition',
    ('core-events-v1', 'alert.resolved'): 'as `alert.fired`: a transition word, and a recovery here is '
                                          'the same condition with `status: resolved` and severity '
                                          '`info`, so `alert conditions` classifies the condition once and both '
                                          'transitions land on it',
    ('core-events-v1', 'forecast.threshold_predicted'): 'a prediction about a future window, while '
                                                        'every kind here describes the window the '
                                                        'event carries, and intake opens an incident '
                                                        'for any firing event whatever its severity — '
                                                        'so filing it as `threshold` would page as if '
                                                        'a limit had already been crossed. forecast owes '
                                                        'a decision (widen `kind`, or an advisory that '
                                                        'opens nothing), not a mapping',
    ('core-events-v1', 'netpath.path_change'): 'an observed route changed, which is neither '
                                               'declared-versus-observed inventory (`drift`) nor a '
                                               'test that failed (`availability`): path monitoring files the '
                                               'consequence, and a bare path change belongs in the '
                                               'topology read-model (topology read model) or needs a new kind by '
                                               'decision',
    ('core-events-v1', 'netpath.bgp_withdrawal'): 'the BGP feed was culled (dead code; path monitoring names '
                                                 'netpath/bgp.py not ported) — nothing emits it, and a '
                                                 'type with no producer is vocabulary debt',
    ('core-events-v1', 'netpath.bgp_hijack'): 'as `netpath.bgp_withdrawal`; if the feed returns, a '
                                              'hijack is a `security` finding and gets its row then',
    ('core-events-v1', 'netpath.bgp_path_anomaly'): 'as `netpath.bgp_withdrawal`',
    ('core-events-v1', 'netpath.bgp_visibility_drop'): 'as `netpath.bgp_withdrawal`',
    ('alertmanager', 'none'): 'Alertmanager\'s default when nobody set the `severity` label; the '
                              'absence of a severity is not a severity, so refuse the loudness and '
                              'record coverage about the ingest source rather than inventing one',
    ('alertmanager', 'unknown'): 'what v0.1\'s adapter produced for an unrecognised label '
                                 '(`_map_severity`); here it is a refusal so an unclaimed label stays '
                                 'visible instead of becoming a guess about the incident',
    ('signoz', 'unspecified'): 'the OTel token for "no severity recorded"; an absent level is not a '
                              'level — a row that carries none must not be filed as a verdict',
    ('signoz', 'unknown'): 'as `unspecified`',
}

# The two v0.1 type words that only exist prefixed here; the mapping table names them `core.*`.
_V01_CORE_TYPES = {'unnormalized': 'core.unnormalized', 'webhook': 'core.webhook'}

# Which lookups the two unprefixed v0.1 type words need: `classify` folds the alias in so a ported
# adapter passes the string it received and never has to know the prefixing rule.
_CORE_EVENTS = 'core-events-v1'


class VocabularyError(ValueError):
    """A source word this crosswalk does not answer for. Never caught and defaulted."""


def _fold(value: Any) -> str:
    """Normalise a caller's word for lookup: trimmed, lower-cased, and short enough to be a word.

    Every declared word is far under 128 characters, so a longer value cannot match and is folded to
    the truncation — the same bound `state.label` puts on identifiers, applied before a comparison
    rather than after one.
    """
    if not isinstance(value, str):
        raise VocabularyError(f'vocabulary word must be a string, not {type(value).__name__}')
    folded = value.strip().lower()
    if not folded:
        raise VocabularyError('vocabulary word is empty')
    return folded[:128]


def _echo(value: Any) -> str:
    """Render a caller's word inside a refusal sentence without echoing raw request data into it.

    `platform/api.py` answers a refusal with `{'detail': str(exc)}`, so anything this module puts in a
    message can reach an HTTP body: the word is folded, capped and stripped to the character set no
    vocabulary here needs. A non-string is named by its type only, never by its contents.
    """
    if not isinstance(value, str):
        return f'<{type(value).__name__}>'
    folded = value.strip().lower()[:128]
    return ''.join(character if character in _ECHO_SAFE else '?' for character in folded) or '<empty>'


def _record(source: Any) -> SourceVocabulary:
    """Return the declared vocabulary for `source`, refusing one that has never been declared."""
    key = source if isinstance(source, str) else None
    record = SOURCE_VOCABULARIES.get(key or '')
    if record is None:
        raise VocabularyError(f'no event vocabulary declared for source {_echo(source)}; declared: '
                              + ', '.join(sorted(SOURCE_VOCABULARIES)))
    return record


def declared_severities(source: str) -> tuple[str, ...]:
    """Every severity word `source` spells, loudest first — mapped, refused or both."""
    return _record(source).severities


def declared_types(source: str) -> tuple[str, ...]:
    """Every type word `source` has an admitted row for, sorted for a stable listing.

    A producer's start-up self-check: a rule whose type is absent from this list has not been
    crosswalked yet, and the card that adds it owns the row here and the table in
    `docs/CONTRACTS.md` §4 in the same diff. Words refused by design are not listed here;
    `refusals` names those, each with its reason.
    """
    record = _record(source)
    return tuple(sorted(word for (name, word) in TYPE_CROSSWALK if name == record.name))


def refusals(source: str) -> tuple[tuple[str, str], ...]:
    """The (word, reason) pairs `source` spells that get no home here, sorted by word.

    Both halves of the vocabulary share one refusals table, so this lists refused severity words and
    refused type words together; every reason says which it is.
    """
    record = _record(source)
    return tuple(sorted((word, reason) for (name, word), reason in REFUSALS.items() if name == record.name))


def severity(source: str, value: str) -> str:
    """Translate one severity word from `source`'s vocabulary into `info`/`warning`/`critical`.

    Folds case and surrounding space before the lookup. A word with no row raises
    `VocabularyError` naming the source, the word and — when the refusal is a decision rather than an
    omission — the reason: there is no default severity, because a fallback would downgrade a
    verdict somebody measured. A source that spells no severity words at all (`gatus`,
    `healthchecks`, `crowdsec`) refuses every value, including `warning`: its severity is the verdict
    derived by `detections.event`, not an input.

    The row describes the *firing* verdict. A recovery carries `info` — the derived default, and what
    v0.1's own dispatcher did (`alerting/dispatch.py`): a resolved event must not keep the loudness of
    the failure it ended.
    """
    record = _record(source)
    folded = _fold(value)
    mapped = SEVERITY_CROSSWALK.get((record.name, folded))
    if mapped is not None:
        return mapped
    reason = REFUSALS.get((record.name, folded))
    if reason is not None:
        raise VocabularyError(f'{record.name} severity {_echo(value)} is refused by design: {reason}')
    if folded in record.severities:
        raise VocabularyError(f'{record.name} severity {_echo(value)} is declared by that source but '
                              'has no crosswalk row; add the row and the CONTRACTS §4 table line')
    spelled = (', '.join(record.severities) if record.severities
               else 'none — this source spells no severity words, and the verdict derives severity')
    raise VocabularyError(f'{record.name} severity {_echo(value)} is not a word that source spells; '
                          f'it spells: {spelled}. {record.note}')


def classify(source: str, event_type: str) -> tuple[str, str]:
    """Translate one `type` word from `source` into the pair `(kind, condition)`.

    Raises `VocabularyError` for any word with no row, naming the source and the word. The returned
    `condition` is what the emitting producer must pass as its `rule_id`, because
    `detections.event()` sets `condition = rule_id` and takes no other argument: a card that needs a
    condition distinct from its rule identity must widen that factory (alert conditions owns it) rather than
    hand-edit the event here.

    For a source whose type space is not a closed set (`alertmanager`, `signoz`) every value raises,
    and the message names who owes the kind — a rule, never a receiver's guess about a name somebody
    typed.
    """
    record = _record(source)
    folded = _fold(event_type)
    if record.name == _CORE_EVENTS:
        folded = _V01_CORE_TYPES.get(folded, folded)
    pair = TYPE_CROSSWALK.get((record.name, folded))
    if pair is not None:
        return pair
    reason = REFUSALS.get((record.name, folded))
    if reason is not None:
        raise VocabularyError(f'{record.name} type {_echo(event_type)} is refused by design: {reason}')
    if not record.closed_types:
        raise VocabularyError(f'{record.name} declares no closed type vocabulary, so {_echo(event_type)} '
                              f'cannot be classified here. {record.note}')
    raise VocabularyError(f'{record.name} type {_echo(event_type)} has no crosswalk row. {record.note}')


def v01_type(event_type: str) -> str:
    """Map a raw v0.1 `Event.type` onto the word `core-events-v1` declares it under.

    Only the two types `core/events.py` itself emits need it (`unnormalized`, `webhook`): every other
    v0.1 type already carries its package prefix and is looked up verbatim. Kept separate from
    `classify` so the prefixing decision is one call, visible in a diff, instead of a string
    concatenation at every call site — `classify` applies the same mapping itself, so a ported adapter
    may pass the raw v0.1 string and get the prefixed condition back.
    """
    folded = _fold(event_type)
    return _V01_CORE_TYPES.get(folded, folded)
