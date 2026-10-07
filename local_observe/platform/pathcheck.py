"""Path availability verdicts and durable route-change conditions.

gatus for synthetics adopted Gatus as the synthetic engine and kept the bespoke assertion/verdict layer **only where
Gatus cannot express it** — its own words are "path monitoring, 'is it me or them'". This is that
surviving layer. Gatus answers "is this endpoint up"; it cannot answer whether the answer was no
because the endpoint is down, because *this* probe host lost its uplink, or because a shared upstream
carried a whole cluster of targets away. That question is the difference between chasing a phantom at
03:00 and calling the ISP, and it is decided here from probe results alone.

**What the probe data is, and where it comes from.** Nothing in this module measures anything: it
takes a *report* written by an external engine — `mtr`, `fping`, `traceroute`, a Gatus instance, a
home-built prober — and classifies it. Those engines are adopted, never spawned (port table §6, the
`netpath` row: "adopted, never spawned"; `pathcheck_parsers.py` states the two reasons), and
**nothing in this product ships a probe service**: `docs/COMPONENTS.md` §3 excludes a hosted probe
("Remote vantage infrastructure — Future third-party integration; no hosted probe service operated by
this project"), and v0.1's `probe` agent was abandoned for exactly that reason. The operator's overlay
supplies the runner and drops one JSON report per vantage point into the directory named by
`sources.reports_dir` — deployment separation keeps versioned operator data downstream of
the product. The product's half is the read, the verdict and the event.

**A vantage point is a declared resource, or it has no verdict.** v0.1 keyed a probe by a free-text
label; here every vantage point is a canonical inventory UUID (`ProbeObservation.vantage_resource_id`,
`pathcheck_parsers.py`'s `vantage_resource_id` argument), the configured one is resolved against the
index on every round exactly as `detections.evaluate` resolves a rule's resource, and a report whose
vantage does not resolve is dropped rather than believed. The asymmetry is deliberate and pinned by
tests: an undeclared **configured** vantage is a configuration error and refuses the whole round
(producer identity is not something a partial verdict may be built on), while an undeclared vantage
**in someone else's report file** is stale or foreign data — it is excluded, counted in the summary,
and the hole it leaves is what makes the round `indeterminate` rather than confidently wrong.

**The five verdicts, and what each one costs.** `ok`, `target`, `local`, `upstream/route`,
`indeterminate` — v0.1's vocabulary, kept verbatim. `target` when a target fails from every vantage
that probed it; `local` when a vantage fails against everything it probed while others reach those
same targets; `upstream/route` when a shared-ASN cluster of targets is dead everywhere; `ok` when
nothing failed; and `indeterminate` for everything else — including the case v0.1 could not express
because it had no expected set: **what is owed is the product of the two expected sets, and a required
`(target, vantage point)` pair nobody filled makes the verdict `indeterminate`, never `ok`.** Silence is
not health. That is the one place this port is stricter than v0.1, and the reason is the whole point of
the module: `ok` from half the vantage points is a lie about the other half — and `ok` about one target
seen from one probe is a lie about the target nobody probed. The narrower hole is the one that reads as
health today: V1 reports its API, a sibling reports its router, and "2 targets from 2 vantage points,
all reachable" is true of neither reporter, because each one's own list has a blank in it. A vantage
that reported without being expected adds no requirement and satisfies none either, so a sibling's data
may corroborate this producer's verdict and can never complete it.

**A verdict owed to the platform is written down before it is sent.** One round owes one or two events,
and the second can be refused or — the case that matters — accepted and lost on the way back, which the
producer cannot tell from never having been sent. So the exact bytes of the batch, the condition and
route state the round intends to leave behind, and the window they belong to go into the cursor *first*,
and the cursor moves past them only once every one has been accepted. The next round replays those bytes
and reads no report at all: a fresh probe cannot un-owe a conclusion the previous round already reached,
and re-judging instead of replaying is how the `resolved` for an outage never gets filed and the incident
sits open over a network the operator can watch being healthy. Any delivery failure retains the batch:
even an explicit refusal cannot undo earlier commits in that batch. This is `conditions.tick`'s durability rule,
ported for the same reason, with the pair `routes`/`open` added because this producer's pending round
also carries route baselines that may not be re-derived from a later trace.

**How a verdict becomes an event.** Through `detections.event()` and no other door, with the probe
window as its window (aligned to the interval, so a replayed round is the same `source_event_id` and
folds into the row the platform already holds rather than opening a second incident). `kind` is
`availability` for `target`/`local`/`upstream/route` — a test that RAN and failed — and `coverage` for
`indeterminate`, which is the boundary `docs/CONTRACTS.md` §4.1 draws and `vocabulary.TYPE_CROSSWALK`
states: a signal that did not arrive says nothing about the thing it came from, only about the signal.
Filing an `indeterminate` round as firing `availability` would page "something is down" on the
strength of data that is missing, which is the exact failure this module exists to prevent. Each
verdict holds **one** durable condition (`pathcheck.target`, `pathcheck.local`,
`pathcheck.upstream-route`, `pathcheck.coverage`), and a verdict that changes closes the condition it
came from with a `resolved` event before opening the new one, so an operator never reads a stale
attribution as still open. Severity is the factory's (`warning` firing, `info` resolved); this
producer measures no size, so it names none.

**The evidence reference is `observed-snapshot` + `observation_id`, never `gatus-result` — and the
reason is a shape, not a preference.** `state.validate_event` admits `gatus-result` and this module
does not use it, because `gatus-result` names one Gatus result (`detections.gatus_sample` reads that
envelope, and `detection_worker` posts the sample so the reference resolves), while a
multi-vantage verdict rests on *N* probe results across *M* vantage points and `detections.event`
attaches exactly one evidence reference to an event. A reference that named one of those samples
while the verdict read them all would be a pointer at a different claim than the event is making. So
the reference is `observed-snapshot` with `observation_id` set to the digest of the whole observation
set the verdict was computed from — both approved parameters, named at `state.py:1318` (query types)
and `state.py:1328` (parameters). Like the drift producer's, this reference has no evidence *sample*
behind it, so `Store.get_evidence` answers `unavailable` for it until something owns a probe-report
resolver; say so before publishing any claim that this verdict's evidence is re-checkable.

**The BGP feed was dropped by name, not by omission.** dead code culled the stretch tier and names the
BGP feed in its list, so `legacy:netpath/bgp.py` (296 lines, a bgpalerter consumer) is **not ported** and
this tree has no bgpalerter reader. The decision is visible in the code rather than merely absent:
`classify` still takes `bgp_feed`, an absent feed still appends its own degradation note to every
verdict that consulted the seam, a feed that raises still cannot break a verdict, and — the load-
bearing part — **`upstream/route` is computed from probe data alone**. v0.1 already reached it that
way: the cluster rule is "≥ :data:`CLUSTER_MIN_TARGETS` dead targets sharing an ASN", where the ASN
arrives on the observation itself (`ProbeObservation.asn`, optional evidence, never required) and the
feed only ever *corroborated* a conclusion already drawn. Nothing got weaker; what got honest is the
documentation of what the feed was ever used for. A hijack, if the feed ever returns, is a `security`
finding with its own row in `vocabulary.py` (its stated ruling) — not a re-enabling of this seam.

**A route change is a condition whose event this product cannot yet file, and says so.** Path
signatures are tracked per `(vantage_resource_id, target, protocol)` in this producer's own cursor
with a real open/resolve lifecycle (opened when the route in use stops being the route it baselined,
resolved when it comes back), and every transition is in the round summary and the CLI output. What
it does **not** do is POST an event: `vocabulary.REFUSALS` — merged as event vocabulary, and aimed at this card
by name — refuses `netpath.path_change` into the vocabulary ("neither declared-versus-observed
inventory (`drift`) nor a test that failed (`availability`)… needs a new kind by decision"), and
inventing a kind here would be exactly the local mapping `vocabulary.py` exists to prevent. So the
durable half ships now and the event half waits on that decision; the consequence of a route change
that actually costs reachability is *already* filed, by the verdict above, under `availability`.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NamedTuple

from local_observe.credentials import read_credential
from local_observe.http import JsonClient
from local_observe.inventory import index
from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from .detections import event
from .owner import exclusive_owner
from .pathcheck_parsers import (PROTOCOLS, PathParseError, PingReport, TraceReport, analyze_ping,
                                parse_traceroute, require_protocol)
from .state import identifier, label, validate_event

log = get_logger(__name__)

CONFIG_ENVIRONMENT = 'LO_PATHCHECK_CONFIG'
SOURCE_ENVIRONMENT = 'LO_PATHCHECK_SOURCE'
# The sleep between rounds, and the length of the window each round judges and each event carries.
DEFAULT_TICK_SECONDS = 300
# The floor sits above the 60 s clock skew `validate_event` tolerates, so an aligned window is never
# judged against a clock that cannot accept it; the ceiling is 24 h because an event window may never
# exceed seven days and a path verdict older than a day is a verdict about a route nobody watches.
TICK_LIMITS = (60, 86_400)
CONFIG_KEYS = frozenset({'vantage_resource_id', 'targets', 'protocols', 'interval_seconds', 'sources',
                         'cursor'})
SOURCE_KEYS = frozenset({'reports_dir'})
MAX_CONFIG_BYTES = 262_144
MAX_TARGETS = 32
MAX_REPORTS = 8
MAX_REPORT_BYTES = 65_536
MAX_PROBES = 64
MAX_ASN = 32
#: How old an observation may be and still count as a statement about the world. Anything older is
#: dropped and the hole it leaves is reported as a coverage gap: an hour-old "reachable" beside a
#: five-second-old "unreachable" is not a correlation, it is a coin flip dressed as one. The instant
#: is also capped forward (`validate_event` refuses the future); both bounds are refused per record,
#: never clamped.
MAX_OBSERVATION_AGE_SECONDS = 900
FUTURE_SKEW_SECONDS = 60
MAX_CURSOR_BYTES = 1_048_576
#: What a cursor may hold. ``pending`` is optional and that is deliberate: a cursor written before the
#: lost-acknowledgement fix — or by a build rolled back to it — carries the other four keys and still
#: loads, while a cursor written here carries a fifth that a build without the fix refuses rather than
#: misreads as "nothing owed". No version bump is needed for an additive key, and none is claimed.
CURSOR_KEYS = frozenset({'schema_version', 'binding', 'open', 'routes', 'pending', 'settled_end'})
CURSOR_REQUIRED_KEYS = CURSOR_KEYS - {'pending', 'settled_end'}
#: What one owed batch is: the bytes to send again, the window they were computed for (so a reader can
#: re-check their retention against the round that wrote them), and the cursor state to adopt once every
#: one of them has been accepted. ``binding`` rides inside for the reason `conditions.load_cursor` gives:
#: a batch may never be delivered under a configuration that did not write it.
PENDING_KEYS = frozenset({'binding', 'end', 'events', 'open', 'routes'})
#: A round files at most two events — the `resolved` for the condition a moving verdict replaces and the
#: `firing` for the one it means (`verdict_findings`) — so a longer batch on disk is not a batch this
#: producer wrote, and is refused rather than delivered a page at a time.
MAX_PENDING_EVENTS = 2
#: Route keys this producer may hold at once: one per declared target — the protocols a target is
#: probed by share a key space, so the ceiling is targets x protocols and the bound is what keeps a
#: cursor from becoming an unbounded route history.
MAX_ROUTES = MAX_TARGETS * len(PROTOCOLS)
CURSOR_VERSION = 1

# --- the verdict core, ported from `legacy:netpath/reachability.py` (values kept verbatim) -------------
VERDICT_OK = 'ok'
VERDICT_TARGET = 'target'
VERDICT_LOCAL = 'local'
VERDICT_UPSTREAM = 'upstream/route'
VERDICT_INDETERMINATE = 'indeterminate'
VERDICTS = (VERDICT_OK, VERDICT_TARGET, VERDICT_LOCAL, VERDICT_UPSTREAM, VERDICT_INDETERMINATE)
#: A `local` verdict needs this many independent targets failing from one vantage point. One failing
#: target from one vantage is not "many targets from one vantage", and calling it local would send
#: the operator to their own uplink while a real target is down.
LOCAL_MIN_TARGETS = 2
#: An `upstream/route` verdict needs this many dead targets sharing an ASN. One target with an ASN is
#: a target outage wearing a coincidence.
CLUSTER_MIN_TARGETS = 2
#: How many blank `(target, vantage point)` observations one degradation note may name. The ceiling here
#: is targets x vantage points, and a note is reasoning for a log line rather than a table: past the
#: ceiling the rest is counted, never dropped.
MAX_GAP_NOTE_PAIRS = 8
BgpFeed = Callable[[str], list[str]]

# verdict -> (event kind, rule id). `upstream/route` cannot be a rule id verbatim: `state.label`
# admits no slash, so the word is hyphenated and the mapping below is the only place either spelling
# appears. `ok` holds no condition and so maps to nothing.
CONDITION_BY_VERDICT: dict[str, tuple[str, str]] = {
    VERDICT_TARGET: ('availability', 'pathcheck.target'),
    VERDICT_LOCAL: ('availability', 'pathcheck.local'),
    VERDICT_UPSTREAM: ('availability', 'pathcheck.upstream-route'),
    VERDICT_INDETERMINATE: ('coverage', 'pathcheck.coverage'),
}
RULE_PREFIX = 'pathcheck'


class PathCheckError(ValueError):
    """A configuration, a report or a verdict this module refuses. The message names the field."""


@dataclass(frozen=True)
class ProbeObservation:
    """One reachability probe: a target, seen from a declared vantage point, under a protocol.

    :attr:`asn` is the target's origin ASN when the operator's feed knows it (``"AS64500"``). It is
    optional evidence for the upstream cluster rule and never required: dropping the BGP feed (dead code)
    removed the *corroboration*, not the input. :attr:`protocol` exists because a TCP refusal and an
    ICMP timeout from the same vantage are different statements about the same target.
    """
    target: str
    vantage_resource_id: str
    ok: bool
    asn: str | None = None
    protocol: str = 'icmp'


class ReachabilityVerdict(NamedTuple):
    """Blast-radius classification with its evidence and its degradation notes.

    :attr:`affected` names the implicated targets, or the implicated vantage points for `local`; it
    is empty for `ok` and for any verdict degraded to `indeterminate`, because a verdict that cannot
    be reached must not leave behind the implication it did not earn. :attr:`notes` is reasoning for
    the log line and the CLI body — a canonical event carries no summary field, so these never reach
    a pager. :attr:`coverage_gaps` is the machine-readable form of the blank pairs the notes describe
    in prose: `classify` normalises both halves (a label, a canonical UUID), and a round summary that
    re-derived them would be a second, possibly disagreeing, answer to "who never looked".
    """
    verdict: str
    affected: tuple[str, ...]
    failing: tuple[tuple[str, str], ...]
    notes: tuple[str, ...]
    coverage_gaps: tuple[tuple[str, str], ...] = ()


def _target_name(value: Any) -> str:
    """Return a bounded target label; a target is the one free-text field an operator types here."""
    try:
        return label(value)
    except Exception:
        raise PathCheckError('target must be a bounded label of 1-128 characters') from None


def _asn(value: Any) -> str | None:
    """Return an ASN annotation as ``AS<digits>`` (or None); refuse anything shaped differently."""
    if value is None:
        return None
    if not isinstance(value, str) or not 3 <= len(value) <= MAX_ASN or not value.startswith('AS') \
            or not value[2:].isdigit():
        raise PathCheckError('asn must be null or AS followed by digits')
    return value


def classify(observations: Sequence[ProbeObservation], *,
             expected_vantage_points: Sequence[str] = (), expected_targets: Sequence[str] = (),
             bgp_feed: BgpFeed | None = None) -> ReachabilityVerdict:
    """Classify blast radius from probe observations alone. Ported nearly verbatim from v0.1.

    For a duplicated `(target, vantage, protocol)` triple the **last** observation wins, which is how
    a caller replays a corrected probe without rewriting history. Protocols are folded after that:
    within one round a vantage *reaches* a target only if **every** protocol probed for that pair
    reached it, so `failing` names `(target, vantage)` pairs and a TCP refusal next to a clean ICMP is
    a failure and not a coin toss between two packets. Folding is the one place this port is not
    byte-for-byte v0.1, and it is forced by the protocol field v0.1's `reachability.py` never carried.
    An empty observation set raises: a verdict is never fabricated from no data, and the caller that
    has no observations says so itself (`tick` files `indeterminate` coverage about its own sources
    rather than asking this function to invent a shape for "nothing").

    ``expected_vantage_points`` / ``expected_targets`` are v0.1's missing half and the only addition to
    the classifier, and they are honoured **pairwise**: what is owed is the product of the two sets, so
    every expected vantage point owes an observation of every expected target and one blank pair degrades
    the verdict to `indeterminate` however firm the rest of the grid looks. A vantage point that reported
    without being expected adds no requirement, and one that was expected owes the whole target list:
    reporting for something else is not a statement about the target this process was configured to
    watch. A pair already observed satisfies once, and repeating it satisfies no better.

    A required observation is one `(target, vantage point)` pair and never one per protocol. Protocols
    are the filter `load_reports` applies to what a report may say — an out-of-scope probe is excluded
    and counted, and a report with nothing in scope is refused as a configuration mismatch rather than
    read as silence — and inside a pair, every protocol that did report must have reached for the pair
    to count as reached. So a configured protocol nobody probed is not its own blank cell: the hole is
    the pair's, which is what keeps `local` meaning "this vantage could not reach these targets" rather
    than "this vantage did not send this packet type".

    ``bgp_feed`` is the culled seam — see the module docstring — and passing None is the shipped
    behaviour.

    Raises:
        PathCheckError: The set is empty, holds a value that is not a :class:`ProbeObservation`, a
            target or vantage that is not a bounded label / canonical UUID, a non-boolean ``ok``, or
            a protocol outside :data:`pathcheck_parsers.PROTOCOLS`.
    """
    if not observations:
        raise PathCheckError('no probe observations: refusing to fabricate a verdict')
    last_ok: dict[tuple[str, str, str], bool] = {}
    probes: dict[tuple[str, str], set[str]] = {}
    asn_of: dict[str, str] = {}
    for item in observations:
        if not isinstance(item, ProbeObservation):
            raise PathCheckError('observations must be ProbeObservation records')
        if not isinstance(item.ok, bool):
            raise PathCheckError('observation ok must be a boolean')
        target, vantage = _target_name(item.target), identifier(item.vantage_resource_id)
        protocol = item.protocol
        if protocol not in PROTOCOLS:
            raise PathCheckError(f'observation protocol must be one of {", ".join(PROTOCOLS)}')
        last_ok[(target, vantage, protocol)] = item.ok
        probes.setdefault((target, vantage), set()).add(protocol)
        if item.asn is not None:
            asn_of[target] = _asn(item.asn)
    expected_vp = tuple(sorted({identifier(item) for item in expected_vantage_points}))
    expected_target = tuple(sorted({_target_name(item) for item in expected_targets}))

    keyed = {pair: all(last_ok[(pair[0], pair[1], protocol)] for protocol in seen)
             for pair, seen in probes.items()}
    targets = sorted({target for target, _ in keyed})
    vantage_points = sorted({vantage for _, vantage in keyed})
    failing = tuple(sorted(pair for pair, ok in keyed.items() if not ok))
    notes: list[str] = []
    verdict, affected, suspects = _classify_pattern(keyed, targets, vantage_points, failing, asn_of,
                                                    notes)
    verdict, affected, gaps = _degrade_for_gaps(verdict, affected, expected_vp, expected_target,
                                                keyed, notes)
    notes.extend(_bgp_notes(bgp_feed, verdict, suspects))
    return ReachabilityVerdict(verdict=verdict, affected=affected, failing=failing, notes=tuple(notes),
                               coverage_gaps=tuple(gaps))


def _classify_pattern(keyed: Mapping[tuple[str, str], bool],
                      targets: list[str], vantage_points: list[str],
                      failing: tuple[tuple[str, str], ...], asn_of: Mapping[str, str],
                      notes: list[str]) -> tuple[str, tuple[str, ...], list[str]]:
    """The correlation itself, v0.1's lines in v0.1's order. Returns (verdict, affected, suspect ASNs)."""
    if not failing:
        # The numbers are of what the data covers, not of what was owed: "2 targets, 2 vantage points"
        # is a count of reporters and names, and `_degrade_for_gaps` below is what says whether the grid
        # between them was actually filled in. v0.1's wording (`all N from all M`) read as a completion
        # claim on a partial round, which is the sentence this module must never print over a gap.
        notes.append(f'no failing pair: {len(targets)} target(s) reachable across '
                     f'{len(vantage_points)} vantage point(s) on {len(keyed)} observed pair(s)')
        return VERDICT_OK, (), []

    vps_probing = {target: sorted(vantage for (inner, vantage) in keyed if inner == target)
                   for target in targets}
    targets_probed = {vantage: sorted(target for (target, inner) in keyed if inner == vantage)
                      for vantage in vantage_points}
    # Dead targets: failing from EVERY vantage point that probed them.
    dead_targets = [target for target in targets
                    if all(not keyed[(target, vantage)] for vantage in vps_probing[target])]
    # Local vantage points: everything they probed fails, each of those targets succeeds from
    # somewhere else, and they probed enough targets for the pattern to mean anything.
    local_vps = [vantage for vantage in vantage_points
                 if len(targets_probed[vantage]) >= LOCAL_MIN_TARGETS
                 and all(not keyed[(target, vantage)] for target in targets_probed[vantage])
                 and all(target not in dead_targets for target in targets_probed[vantage])]

    if local_vps and not dead_targets:
        notes.append(f"all targets fail from vantage point(s) {', '.join(local_vps)} and succeed "
                     'from elsewhere: fault is local to that vantage point')
        return VERDICT_LOCAL, tuple(local_vps), []

    asn_groups: dict[str, list[str]] = {}
    for target in dead_targets:
        asn = asn_of.get(target)
        if asn:
            asn_groups.setdefault(asn, []).append(target)
    clusters = {asn: sorted(group) for asn, group in asn_groups.items()
                if len(group) >= CLUSTER_MIN_TARGETS}
    if clusters:
        affected: list[str] = []
        for asn in sorted(clusters):
            affected.extend(clusters[asn])
            notes.append(f"targets {', '.join(clusters[asn])} share {asn} and all fail from every "
                         'vantage point: shared upstream/route fault suspected')
        if local_vps:
            notes.append(f"vantage point(s) {', '.join(local_vps)} additionally fail to all targets")
        # Reached with no BGP feed at all: the ASN rides the observation, the feed never decided this.
        return VERDICT_UPSTREAM, tuple(sorted(set(affected))), sorted(clusters)

    if dead_targets:
        notes.append(f"target(s) {', '.join(dead_targets)} fail from every vantage point that probed "
                     'them; other targets are unaffected: fault is at the target')
        if local_vps:
            notes.append(f"vantage point(s) {', '.join(local_vps)} additionally fail to all targets")
        return VERDICT_TARGET, tuple(dead_targets), []

    notes.append(f'partial failures without a clear blast-radius pattern ({len(failing)} failing '
                 'pair(s)): indeterminate')
    return VERDICT_INDETERMINATE, tuple(sorted({target for target, _ in failing})), []


def _coverage_gaps(keyed: Mapping[tuple[str, str], bool], expected_vp: Sequence[str],
                   expected_target: Sequence[str]) -> tuple[list[str], list[str],
                                                            list[tuple[str, str]]]:
    """Return the reporters that said nothing, the targets nobody probed, and the blank required pairs.

    The three answers describe one hole each, and only the third is invisible to the other two: a blank
    pair inside a vantage point that went quiet entirely is already `missing_vp`, and a target nobody
    probed anywhere is already `missing_target`. `missing_pairs` is the narrower case both of those wave
    past — the reporter DID report and the target WAS probed, just never from the vantage point that owed
    the observation — which is the shape that used to read as a healthy network. The pair list is the
    complete owed-and-absent set, so a round summary can name every hole structurally; the notes below
    are allowed to group them into sentences instead.
    """
    observed = set(keyed)
    seen_targets = {target for target, _vantage in observed}
    seen_vantages = {vantage for _target, vantage in observed}
    missing_vp = [vantage for vantage in expected_vp if vantage not in seen_vantages]
    missing_target = [target for target in expected_target if target not in seen_targets]
    missing_pairs = sorted((target, vantage) for vantage in expected_vp for target in expected_target
                           if (target, vantage) not in observed)
    return missing_vp, missing_target, missing_pairs


def _degrade_for_gaps(verdict: str, affected: tuple[str, ...], expected_vp: tuple[str, ...],
                      expected_target: tuple[str, ...], keyed: Mapping[tuple[str, str], bool],
                      notes: list[str]) -> tuple[str, tuple[str, ...], list[tuple[str, str]]]:
    """Downgrade to `indeterminate` when a required observation is missing. The stricter half of v0.1.

    A vantage point that probed nothing is not a vantage point that saw nothing wrong: it is the
    absence of a statement, and `ok` read from the remaining vantages would be a claim about the
    missing one. The same is true of the narrower hole — a vantage that probed *something*, but never
    the target it was configured to watch, has said nothing about that target, and its gap may not be
    filled from a sibling's report, because the sibling is a different reporter with a different view.
    Coverage is therefore never "some pairs arrived" but "every pair this configuration owed did".
    The pattern the data *would* have supported stays in the notes, because "looks local, but the
    second probe never reported" is a more useful sentence than either word alone.

    Returns the blank pairs beside the verdict so the round summary can name them without re-normalising
    the observations; a degraded verdict carries no `affected` set either way.
    """
    missing_vp, missing_target, missing_pairs = _coverage_gaps(keyed, expected_vp, expected_target)
    if not missing_vp and not missing_target and not missing_pairs:
        return verdict, affected, []
    if missing_vp:
        notes.append(f'vantage point(s) {", ".join(missing_vp)} reported no probe: no verdict about '
                     'their view of the targets')
    if missing_target:
        notes.append(f'configured target(s) {", ".join(missing_target)} were not probed by any '
                     'vantage point')
    if missing_pairs:
        # Only the pairs that neither of the two sentences above already names: "V2 went quiet" says more
        # than a list of its blanks, and "nobody probed T9" says more than one line per expected vantage.
        narrow = [(target, vantage) for target, vantage in missing_pairs
                  if vantage not in missing_vp and target not in missing_target]
        if narrow:
            named = ', '.join(f'{target} from {vantage}'
                              for target, vantage in narrow[:MAX_GAP_NOTE_PAIRS])
            rest = len(narrow) - MAX_GAP_NOTE_PAIRS
            notes.append(f'no observation of {named}{f" and {rest} more pair(s)" if rest > 0 else ""}: '
                         'those vantage points reported, but not about these targets, so the verdict '
                         'cannot borrow another reporter\'s view of them')
    if verdict != VERDICT_INDETERMINATE:
        notes.append(f'pattern in the data that did arrive was "{verdict}"; the verdict is '
                     f'{VERDICT_INDETERMINATE} because a verdict is only as firm as the coverage it '
                     'was computed from')
    return VERDICT_INDETERMINATE, (), missing_pairs


def _bgp_notes(bgp_feed: BgpFeed | None, verdict: str, suspect_asns: Sequence[str]) -> list[str]:
    """The optional-dependency seam, ported: corroborate, degrade visibly, never crash.

    An absent feed appends its own note and the verdict stands unchanged — which is the shipped path,
    because dead code culled the feed. A feed that raises is caught here and reported as a note: a broken
    corroboration source may not be able to un-classify a verdict the probes already supported, and
    it may certainly not end the round.
    """
    if bgp_feed is None:
        return ['bgp feed absent: verdict derived from probe data alone (degraded)']
    if verdict != VERDICT_UPSTREAM:
        return []
    notes: list[str] = []
    for asn in suspect_asns:
        try:
            anomalies = bgp_feed(asn)
        except Exception as exc:  # a broken feed must never break the verdict
            notes.append(f'bgp feed errored for {asn}: {exc}; verdict derived from probe data alone '
                         '(degraded)')
            continue
        notes.append(f'bgp feed corroborates {asn}: {" ; ".join(anomalies)}' if anomalies
                     else f'bgp feed shows no anomalies for {asn}')
    return notes


def observation_digest(observations: Sequence[ProbeObservation], window: Mapping[str, str]) -> str:
    """Return the evidence id for the exact observation set a verdict was computed from.

    The window is an input, not decoration: the same probe results read into a later round are a
    different statement, and a reviewer who has the digest and this function can reproduce which
    round said what. Sixty-four lowercase hex, inside the 1-256 character bound `validate_event` puts
    on an evidence parameter and inside `state.label` besides, so the value can also be posted as a
    ``sample_id`` by anything that later files the samples behind it.
    """
    rows = sorted([[item.target, item.vantage_resource_id, item.protocol, item.ok, item.asn]
                   for item in observations])
    return digest([utc_text(timestamp(window['start'])), utc_text(timestamp(window['end'])), rows])


def verdict_findings(verdict: ReachabilityVerdict, *, source: str, vantage_resource_id: str,
                     window: Mapping[str, str], observations: Sequence[ProbeObservation],
                     open_finding: Mapping[str, str] | None) -> tuple[list[dict[str, Any]],
                                                                      dict[str, str] | None]:
    """Turn a verdict into the events this round owes, and say which condition is now open.

    One condition at a time on this channel: an operator holding two of `target` and `local` open at
    once is holding a contradiction, so a verdict that moves resolves what it replaced before it
    fires what it means. A verdict that has not moved owes nothing at all — including when it is bad
    news, which is already open and already paged; re-filing it every round would be a producer
    paging itself, and the outbox is where the noise decision belongs.

    Returns ``(events, open)`` where ``open`` is the finding the next round must compare against
    (``None`` after an `ok` verdict, which closes whatever was open and opens nothing).
    """
    wanted = CONDITION_BY_VERDICT.get(verdict.verdict)
    reference = {'observation_id': observation_digest(observations, window)}
    events: list[dict[str, Any]] = []
    if open_finding and (wanted is None or wanted[1] != open_finding['rule_id']):
        events.append(event(source, vantage_resource_id, open_finding['rule_id'], open_finding['kind'],
                            'resolved', dict(window), {**reference, 'rule_id': open_finding['rule_id']},
                            query_type='observed-snapshot'))
    if wanted and (open_finding is None or wanted[1] != open_finding['rule_id']):
        kind, rule = wanted
        events.append(event(source, vantage_resource_id, rule, kind, 'firing', dict(window),
                            {**reference, 'rule_id': rule}, query_type='observed-snapshot'))
        return events, {'kind': kind, 'rule_id': rule}
    return events, (None if wanted is None else dict(open_finding or {}))


# --- the route-changed condition (durable state; see the module docstring for the event refusal) ----
class RouteFinding(NamedTuple):
    """One route-transition the operator should see, and the two signatures it moved between.

    :attr:`transition` is `opened`, `resolved` or `held` — `held` names the case with no transition:
    still off the baseline, still the same alternate route, which is reported so a quiet round is
    distinguishable from a round that agrees the route is fine. Never an event: see
    :data:`vocabulary.REFUSALS` on `netpath.path_change`.
    """
    vantage_resource_id: str
    target: str
    protocol: str
    transition: str
    baseline_signature: str
    previous_signature: str
    current_signature: str
    hop_count: int
    observed_at: str

    def as_dict(self) -> dict[str, Any]:
        """Return the summary form: digests and counts, no hop list, which is what a log line may hold."""
        return {'vantage_resource_id': self.vantage_resource_id, 'target': self.target,
                'protocol': self.protocol, 'transition': self.transition,
                'baseline_signature': self.baseline_signature,
                'previous_signature': self.previous_signature,
                'current_signature': self.current_signature, 'hop_count': self.hop_count,
                'observed_at': self.observed_at}


def route_key(vantage_resource_id: str, target: str, protocol: str) -> str:
    """Return the one cursor key for one `(vantage, target, protocol)` triple.

    Joined on ``|``, which no component can contain: a vantage is a canonical UUID, a protocol comes
    from a closed set and a target is a `state.label`-bounded name. That makes the key injective
    without an escaping rule to get wrong, and it keeps the cursor readable next to its digests.
    """
    return f'{identifier(vantage_resource_id)}|{_target_name(target)}|{protocol}'


def observe_routes(state: dict[str, dict[str, str]], traces: Sequence[TraceReport], *,
                   observed_at: str) -> list[RouteFinding]:
    """Update the route baselines in *state* and return what each trace is worth reporting.

    A never-seen route is baselined and reports nothing — v0.1's rule, and the right one: a producer
    that fired on its own first round would page for the route it happened to boot onto. From then on
    the condition means **"the route in use is not the route this producer baselined"**: it opens on
    the first signature change and resolves only when the signature comes back. A change to a *third*
    route holds the condition open rather than closing it, because closing on any later change would
    tell the operator the route had recovered when all that happened is that it moved again.

    A later route change does not itself establish recovery. This
    is stated rather than buried: with `opened`/`resolved` transitions per key in the summary, the
    two readings differ on exactly one sequence (A -> B -> C) and this one never claims recovery that
    nobody observed. Re-baselining is an operator action: remove the cursor (the next round baselines
    what it now sees and reports nothing until the route moves again).
    """
    findings: list[RouteFinding] = []
    for trace in traces:
        key = route_key(trace.vantage_resource_id, trace.target, trace.protocol)
        record = state.get(key)
        signature = trace.path_signature
        if record is None:
            if len(state) >= MAX_ROUTES:
                raise PathCheckError(f'route state holds the maximum of {MAX_ROUTES} keys; remove '
                                     'the cursor to re-baseline')
            state[key] = {'baseline': signature, 'signature': signature, 'open': 'no'}
            continue
        baseline, previous, open_now = record['baseline'], record['signature'], record['open']
        if signature == baseline:
            transition, open_after = ('resolved', 'no') if open_now == 'yes' else ('stable', 'no')
        elif open_now == 'yes':
            transition, open_after = 'held', 'yes'
        else:
            transition, open_after = 'opened', 'yes'
        state[key] = {'baseline': baseline, 'signature': signature, 'open': open_after}
        if transition != 'stable':
            findings.append(RouteFinding(trace.vantage_resource_id, trace.target, trace.protocol,
                                         transition, baseline, previous, signature, trace.hop_count,
                                         observed_at))
    return findings


# --- configuration, reports, cursor (the bounded-IO half) ---------------------------------------------
def _absolute(value: Any, field: str) -> Path:
    """Return *value* as an absolute path. A relative one means "wherever the process started"."""
    if not isinstance(value, str) or not value.strip():
        raise PathCheckError(f'configuration {field} must name a path')
    path = Path(value)
    if not path.is_absolute():
        raise PathCheckError(f'configuration {field} must be an absolute path')
    return path


def load_config(path: Path | str) -> dict[str, Any]:
    """Read and validate the JSON document ``LO_PATHCHECK_CONFIG`` names; every refusal names a field.

    ``{"vantage_resource_id": <uuid>, "targets": [label...], "protocols": [icmp|tcp|udp],
    "interval_seconds": <int>, "sources": {"reports_dir": <abs path>}, "cursor": <abs file>}``. The
    document describes **one vantage point**: the producer is the probe host's own reader, and other
    vantage points contribute by writing their own report files into the shared directory. Only
    ``interval_seconds`` is defaulted — a producer that guessed a target list would report "ok" about
    endpoints it was never told to watch.

    ``cursor`` is required: the
    route baselines and the open condition are what make a second round mean something different from
    the first, and v0.1's `PathTracker` held them in process memory, which made every restart a
    re-baseline. It sits in the document, as the drift producer's does, because it is state this
    producer is not allowed to invent a location for.
    """
    candidate = Path(path)
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError(f'{CONFIG_ENVIRONMENT} document exceeds {MAX_CONFIG_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError(f'{CONFIG_ENVIRONMENT} is not JSON') from None
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise ValueError(f'Pathcheck configuration holds unknown keys or is not an object; expected '
                         f'{", ".join(sorted(CONFIG_KEYS))}')
    missing = CONFIG_KEYS - {'interval_seconds'} - set(document)
    if missing:
        raise ValueError(f'Pathcheck configuration is missing {", ".join(sorted(missing))}')
    interval = document.get('interval_seconds', DEFAULT_TICK_SECONDS)
    if (isinstance(interval, bool) or not isinstance(interval, int)
            or not TICK_LIMITS[0] <= interval <= TICK_LIMITS[1]):
        raise ValueError(f'Pathcheck interval_seconds must be a whole number of seconds from '
                         f'{TICK_LIMITS[0]} to {TICK_LIMITS[1]}')
    try:
        vantage = identifier(document['vantage_resource_id'])
    except Exception:
        raise ValueError('Pathcheck vantage_resource_id must be a canonical declared UUID') from None
    targets = document['targets']
    if not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError(f'Pathcheck targets must be a list of 1..{MAX_TARGETS} bounded labels')
    try:
        targets = sorted({_target_name(item) for item in targets})
    except PathCheckError as exc:
        raise ValueError(str(exc)) from None
    protocols = document['protocols']
    if (not isinstance(protocols, list) or not 1 <= len(protocols) <= len(PROTOCOLS)
            or any(item not in PROTOCOLS for item in protocols)):
        raise ValueError(f'Pathcheck protocols must be 1..{len(PROTOCOLS)} of {", ".join(PROTOCOLS)}')
    sources = document['sources']
    if not isinstance(sources, dict) or set(sources) != SOURCE_KEYS:
        raise ValueError(f'Pathcheck sources must name exactly {", ".join(sorted(SOURCE_KEYS))}')
    return {'vantage_resource_id': vantage, 'targets': targets, 'protocols': sorted(set(protocols)),
            'interval_seconds': int(interval), 'sources': {'reports_dir': _absolute(sources['reports_dir'],
                                                                                   'sources.reports_dir')},
            'cursor': _absolute(document['cursor'], 'cursor')}


def producer_config(environment: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return the validated configuration, or None when the producer is not configured at all.

    An unset or blank ``LO_PATHCHECK_CONFIG`` is the documented off switch and answers one INFO line
    naming the variable — the rule every optional producer here follows (`anomaly`, `configdrift`), so
    "off" means the same thing across the package. A file that is named and cannot be read or parsed
    is not off: it raises, and `main` exits 1, because a producer that survived a broken config would
    be reporting a clean network on the strength of nothing at all.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Pathcheck producer is off; no configuration named',
                 extra={'variable': CONFIG_ENVIRONMENT})
        return None
    return load_config(raw)


class Report(NamedTuple):
    """One vantage point's report: its observations, its traces, its latency analysis, when it says it
    measured, and what inside it was out of scope for this configuration."""
    vantage_resource_id: str
    observed_at: str
    observations: tuple[ProbeObservation, ...]
    traces: tuple[TraceReport, ...]
    latency: tuple[PingReport, ...]
    out_of_scope: int


PROBE_KEYS = frozenset({'target', 'ok', 'asn', 'protocol', 'rtts_ms'})
TRACE_KEYS = frozenset({'target', 'protocol', 'hops'})
REPORT_KEYS = frozenset({'schema_version', 'vantage_resource_id', 'observed_at', 'probes', 'traces'})
#: How many latency rows one round may print. A probe runner can write hundreds of series; the
#: verdict reads all of them and the operator's terminal reads the first `MAX_LATENCY_ROWS`, with the
#: remainder counted rather than quietly dropped.
MAX_LATENCY_ROWS = 64


def _probe_record(raw: Any, *, vantage: str) -> ProbeObservation:
    """Return one probe result as an observation, refusing a record that is not one.

    ``rtts_ms`` is accepted here and ignored by the verdict on purpose: the latency series belongs to
    `pathcheck_parsers.analyze_ping`, which reads the same record into a loss/jitter report right
    beside this one. A verdict over "did it answer" and a measurement of "how badly did it answer"
    are two sentences, and keeping them in two functions is what stops one silently overriding the
    other — a 100 %-loss series and an `ok: true` flag arrive in the same record and are both true.
    """
    if not isinstance(raw, dict) or not {'target', 'ok'} <= set(raw) or set(raw) - PROBE_KEYS:
        raise PathCheckError('a probe record names target, ok and optionally asn, protocol, rtts_ms')
    if not isinstance(raw['ok'], bool):
        raise PathCheckError('probe ok must be a boolean')
    return ProbeObservation(target=_target_name(raw['target']), vantage_resource_id=vantage,
                            ok=raw['ok'], asn=_asn(raw.get('asn')),
                            protocol=require_protocol(raw.get('protocol', 'icmp')))


def _latency_report(raw: Any, *, vantage: str) -> PingReport | None:
    """Analyze one probe record's RTT series, or say there is none to analyze.

    A record without ``rtts_ms`` is a boolean and nothing more, which is legal: the verdict needs the
    boolean, and an absent series is not a series of zeros. A record that *does* name one is held to
    the parser's bounds, so a malformed series refuses the report instead of vanishing from it.
    """
    if 'rtts_ms' not in raw:
        return None
    return analyze_ping(raw['rtts_ms'], vantage_resource_id=vantage, target=raw['target'],
                        protocol=raw.get('protocol', 'icmp'))


def load_reports(directory: Path | str, *, protocols: Sequence[str],
                 before: dt.datetime) -> dict[str, Any]:
    """Read the operator's probe reports: ``{'reports', 'stale', 'unparseable', 'blind', 'reason', ...}``.
    One JSON file per vantage point, sorted by name so a round is reproducible:

    ``{"schema_version": 1, "vantage_resource_id": <uuid>, "observed_at": <utc>, "probes":
    [{"target", "ok", "asn"?, "protocol"?, "rtts_ms"?}], "traces"?: [{"target", "protocol",
    "hops": [{"ttl", "address"?, "rtts_ms"}]}]}``

    Nothing here spawns, measures or accepts a path the operator did not name: the directory is read
    read-only, a symlink is refused rather than followed out of it, and a file over
    :data:`MAX_REPORT_BYTES` is refused rather than truncated (a report cut in half is a report about
    the targets that survived the cut). Unparseable files are counted and skipped — one corrupt
    vantage may not silence the others — while an absent directory is `blind`, which is the
    round-level fact the summary and the coverage condition are built from. An observation older than
    :data:`MAX_OBSERVATION_AGE_SECONDS`, or from the future, is dropped and counted: it is not a
    statement about the window this round judges.

    A probe or trace whose protocol this configuration did not ask for is **excluded and counted**
    (`out_of_scope`), not fatal to its file and not folded into the verdict either: the operator named
    the protocols they wanted compared, and a silent widening of that set would change what `local`
    means while appearing to obey the configuration.

    The ``rtts_ms`` series ride along: `pathcheck_parsers.analyze_ping` turns each one into a loss and
    latency row that the round summary carries beside the verdict, while the verdict itself reads only
    the boolean. That split is the reason the parsers are a separate module — "did it answer" and "how
    badly did it answer" are two sentences about one probe, and only the first may open a condition.
    """
    root = Path(directory)
    out: dict[str, Any] = {'reports': [], 'stale': 0, 'unparseable': 0, 'oversize': 0, 'excess': 0,
                           'out_of_scope': 0, 'blind': False, 'reason': None}
    if not root.is_dir():
        out['blind'], out['reason'] = True, 'reports_directory_absent'
        return out
    try:
        names = sorted(item for item in root.iterdir() if item.is_file())
    except OSError:
        out['blind'], out['reason'] = True, 'reports_directory_unreadable'
        return out
    if not names:
        out['blind'], out['reason'] = True, 'reports_directory_empty'
        return out
    out['excess'] = max(0, len(names) - MAX_REPORTS)
    for path in names[:MAX_REPORTS]:
        try:
            if path.is_symlink():
                raise PathCheckError('refusing a report that is a symlink out of the tree')
            with path.open('rb') as stream:
                raw = stream.read(MAX_REPORT_BYTES + 1)
            if len(raw) > MAX_REPORT_BYTES:
                out['oversize'] += 1
                continue
            document = json.loads(raw)
        except (OSError, ValueError, UnicodeDecodeError):
            out['unparseable'] += 1
            continue
        try:
            report = _report_document(document, protocols=protocols, before=before)
        except (PathParseError, PathCheckError, ValueError):
            out['unparseable'] += 1
            continue
        if report is None:
            out['stale'] += 1
            continue
        out['out_of_scope'] += report.out_of_scope
        out['reports'].append(report)
    if not out['reports'] and not out['blind']:
        out['blind'], out['reason'] = True, 'no_report_current'
    return out


def _report_document(document: Any, *, protocols: Sequence[str],
                     before: dt.datetime) -> Report | None:
    """Return the report one document holds, or None when its own timestamp says it is stale.

    A report whose probes all came in on protocols nobody asked for is refused rather than returned
    empty: an empty report from a live vantage would read as "that vantage probed nothing", which is
    the coverage gap this module files a condition about, when the truth is a configuration mismatch.
    """
    wanted = set(protocols)
    if (not isinstance(document, dict) or set(document) - REPORT_KEYS
            or not REPORT_KEYS - {'traces'} <= set(document)):
        raise PathCheckError('a report names schema_version, vantage_resource_id, observed_at, '
                             'probes and optionally traces')
    if document['schema_version'] != 1:
        raise PathCheckError('unsupported report schema_version')
    vantage = identifier(document['vantage_resource_id'])
    observed = timestamp(document['observed_at'])
    if observed > before + dt.timedelta(seconds=FUTURE_SKEW_SECONDS):
        raise PathCheckError('a report may not name the future')
    if observed < before - dt.timedelta(seconds=MAX_OBSERVATION_AGE_SECONDS):
        return None
    probes = document['probes']
    if not isinstance(probes, list) or not 1 <= len(probes) <= MAX_PROBES:
        raise PathCheckError(f'probes must be a list of 1..{MAX_PROBES} records')
    parsed = [(_probe_record(item, vantage=vantage), _latency_report(item, vantage=vantage))
              for item in probes]
    traces_raw = document.get('traces')
    if traces_raw is not None and (not isinstance(traces_raw, list) or len(traces_raw) > MAX_TARGETS):
        raise PathCheckError(f'traces must be a list of at most {MAX_TARGETS} records')
    in_scope = [(record, latency) for record, latency in parsed if record.protocol in wanted]
    observations = tuple(record for record, _latency in in_scope)
    latency = tuple(item for _record, item in in_scope if item is not None)
    traces: list[TraceReport] = []
    for raw in traces_raw or []:
        if not isinstance(raw, dict) or set(raw) != TRACE_KEYS:
            raise PathCheckError('a trace names target, protocol and hops')
        if raw['protocol'] not in wanted:
            continue
        traces.append(parse_traceroute(raw['hops'], vantage_resource_id=vantage, target=raw['target'],
                                       protocol=require_protocol(raw['protocol'])))
    skipped = len(parsed) - len(in_scope) + len(traces_raw or []) - len(traces)
    if not observations:
        raise PathCheckError('no probe in this report speaks a configured protocol')
    return Report(vantage, utc_text(observed), observations, tuple(traces), latency, skipped)


def cursor_binding(config: Mapping[str, Any]) -> str:
    """Return the digest of *what is watched*: the vantage, its targets and protocols, and the tree.

    Excludes ``interval_seconds`` and the cursor path — those change how often a verdict is reached,
    not which probe results a stored route baseline is a statement about — because a cursor must not
    be thrown away for a retune. Including the reports directory is what makes a moved mount a
    refusal instead of a comparison against someone else's baseline.
    """
    return digest([config['vantage_resource_id'], sorted(config['targets']),
                   sorted(config['protocols']), str(config['sources']['reports_dir'])])


def _checked_open(value: Any) -> None:
    """Refuse an open-finding record this producer could not have written, naming nothing but the field."""
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {'kind', 'rule_id'}:
        raise ValueError('Pathcheck cursor holds an unreadable open finding')
    try:
        label(value['rule_id'])
    except Exception:
        raise ValueError('Pathcheck cursor holds an unreadable open finding') from None
    if value['kind'] not in ('availability', 'coverage'):
        raise ValueError('Pathcheck cursor holds an open finding of a kind it never files')


def _checked_routes(routes: Any) -> None:
    """Refuse a route table this producer could not have written, field by field."""
    if not isinstance(routes, dict) or len(routes) > MAX_ROUTES:
        raise ValueError('Unsupported pathcheck cursor document')
    for key, record in routes.items():
        if (not isinstance(key, str) or not isinstance(record, dict)
                or set(record) != {'baseline', 'signature', 'open'} or record['open'] not in ('yes', 'no')):
            raise ValueError('Pathcheck cursor holds an unreadable route record')
        for field in ('baseline', 'signature'):
            if not isinstance(record[field], str) or len(record[field]) != 64:
                raise ValueError('Pathcheck cursor holds a route signature that is not a digest')


def _settled_end(document: Mapping[str, Any]) -> dt.datetime | None:
    """Validate the optional completed-window watermark without inventing one for legacy state."""
    if 'settled_end' not in document:
        return None
    try:
        return timestamp(document['settled_end'])
    except (AttributeError, TypeError, ValueError):
        raise ValueError('Pathcheck cursor holds an unusable completed window') from None


def _checked_pending(pending: Any, binding: str) -> None:
    """Refuse an owed batch that could not be delivered as written.

    The bytes are re-checked with `state.validate_event` rather than restated, for the reason
    `conditions.load_cursor` gives: a cursor that half-parsed would hand a hand-edited verdict to
    intake, and a batch is exactly that dangerous when the producer trusts it enough to replay it
    before looking at the network again. `end` is the instant the batch was computed for, so it is the
    clock the evidence retention is checked against — not now, which would age a owed round out of its
    own cursor while the platform is down.
    """
    if (not isinstance(pending, dict) or set(pending) != PENDING_KEYS
            or pending['binding'] != binding or not isinstance(pending['events'], list)
            or not 1 <= len(pending['events']) <= MAX_PENDING_EVENTS):
        raise ValueError('Pathcheck cursor pending batch is malformed')
    try:
        end = timestamp(pending['end'])
    except Exception:
        raise ValueError('Pathcheck cursor pending batch names no readable window') from None
    for item in pending['events']:
        try:
            validate_event(item, end)
        except ValueError:
            refusal = 'Pathcheck cursor pending batch holds an event that is not canonical'
            raise ValueError(refusal) from None
    _checked_open(pending['open'])
    _checked_routes(pending['routes'])


def load_cursor(path: Path | str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Return this producer's cursor, refusing one that belongs to another configuration.

    ``{'schema_version', 'binding', 'open', 'routes'}``, plus ``pending`` when a round still owes a
    batch. A binding mismatch is never silently re-baselined: a stored route signature from a different
    vantage or a different reports tree, compared against what is read now, manufactures a route change
    out of an unrelated edit — exactly the failure the drift producer refuses for the same reason. The
    structure is checked field by field, because a cursor that half-parses would report a clean network
    from an empty ``routes``.

    A document without ``pending`` is read as one with nothing owed, which is both the legacy cursor
    (four keys, written before this module kept a batch at all) and the shape a rollback writes; it costs
    a producer nothing to upgrade and, on the way back, an unrecognised key is a refusal rather than a
    silently dropped verdict. The key is filled in on the way out for that reason: a caller that has to
    remember which cursors are old is a caller that will eventually guess. A file that does not exist yet
    is an empty document, not a refusal: the first round has nothing owed.
    """
    candidate = Path(path)
    expected = cursor_binding(config)
    if not candidate.exists():
        return {'schema_version': CURSOR_VERSION, 'binding': expected, 'open': None, 'routes': {},
                'pending': None}
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CURSOR_BYTES + 1)
    if len(raw) > MAX_CURSOR_BYTES:
        raise ValueError(f'Pathcheck cursor exceeds {MAX_CURSOR_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('Pathcheck cursor is not JSON') from None
    if (not isinstance(document, dict) or not CURSOR_REQUIRED_KEYS <= set(document)
            or set(document) - CURSOR_KEYS or document['schema_version'] != CURSOR_VERSION):
        raise ValueError('Unsupported pathcheck cursor document')
    if document['binding'] != expected:
        raise ValueError('Pathcheck cursor belongs to a different vantage point, target set or '
                         'reports directory; remove it to re-baseline')
    _checked_open(document['open'])
    _checked_routes(document['routes'])
    _settled_end(document)
    if document.get('pending') is not None:
        _checked_pending(document['pending'], document['binding'])
        return document
    document['pending'] = None
    return document


def _cursor_document(cursor: Mapping[str, Any], *, pending: Mapping[str, Any] | None = None,
                     state: Mapping[str, Any] | None = None, settled_end: str | None = None) -> dict[str, Any]:
    """Return the cursor that remembers *pending* is owed, with the condition state *state* now open.

    One writer for the shape, so the two facts a round can be in — "nothing owed, this is the state"
    and "something owed, the state below is only true once it lands" — cannot drift apart by one of
    them being edited in place. `state` absent means the caller wants the cursor's current state kept,
    including while a new batch is in flight. The completed window advances only after every
    event has been acknowledged.
    """
    settled = state if state is not None else {'open': cursor['open'], 'routes': cursor['routes']}
    document = {'schema_version': CURSOR_VERSION, 'binding': cursor['binding'], 'open': settled['open'],
                'routes': settled['routes'], 'pending': dict(pending) if pending else None}
    end = settled_end if settled_end is not None else cursor.get('settled_end')
    if end is not None:
        document['settled_end'] = end
    return document


def save_cursor(path: Path | str, value: Mapping[str, Any]) -> None:
    """Write the cursor atomically and privately, the way every producer cursor here is written.

    Same durability sequence `detection_worker.save` uses (temporary file, ``fsync``, atomic
    ``os.replace``, directory ``fsync`` off Windows), with the 0600 mode `configdrift.save_cursor`
    picks: this file holds hop addresses and the operator's target names, which is topology rather
    than credentials, but a producer that keeps state should keep it privately and re-set the mode on
    overwrite rather than inherit whatever the umask of the moment was. The parent directory is **not**
    created: the operator names a location for a producer's memory, and a wrong one must refuse loudly
    (`cli.require_cursor_parent` applies the same rule to the one-round path).
    """
    destination = Path(path)
    if not destination.parent.is_dir():
        raise ValueError('Pathcheck cursor parent does not exist; create it before the first round')
    temporary = destination.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    os.replace(temporary, destination)
    if os.name != 'nt':
        handle = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)


def _window(now: dt.datetime, interval_seconds: int) -> dict[str, str]:
    """Return the aligned ``(end - interval, end]`` window this round judges and its events carry."""
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // interval_seconds * interval_seconds,
                                    dt.timezone.utc)
    return {'start': utc_text(end - dt.timedelta(seconds=interval_seconds)), 'end': utc_text(end)}


def _replay(path: Path, cursor: Mapping[str, Any],
            deliver: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    """Send the batch the last round owed, and only then let that round's state become the cursor's.

    Nothing here reads a report, opens the inventory index or asks the classifier an opinion: this round
    has one job, and reading the world while a verdict is unfiled is how the file-never event gets lost.
    The bytes are delivered as stored (`events` is a copy for the summary, not a re-write), so a replay
    is the same `source_event_id` over the same window and `Store.intake` folds the ones that did land
    into `duplicate` answers instead of a second incident.

    Every delivery failure retains the batch. Even an explicit refusal of a later event cannot
    undo an earlier commit, and an exception class cannot prove whether an event was accepted.
    """
    batch = cursor['pending']
    events = [dict(item) for item in batch['events']]
    for item in events:
        deliver(item)
    save_cursor(path, _cursor_document(cursor, state={'open': batch['open'], 'routes': batch['routes']},
                                      settled_end=batch['end']))
    return {'result': 'replayed', 'window': dict(events[0]['window']), 'verdict': None,
            'affected': [], 'failing': [], 'coverage_gaps': [], 'replayed_events': len(events),
            'notes': [f'{len(events)} event(s) owed by the round at {batch["end"]} were replayed from '
                      'the cursor; no report was read and no verdict was computed, because a later '
                      'probe cannot un-owe what that round already concluded'],
            'events': events, 'open_finding': batch['open'], 'observations': 0,
            'probes_by_vantage': {}, 'traces': 0, 'route_findings': [], 'latency': [],
            'latency_rows': 0, 'latency_truncated': False, 'transitions': 0,
            'excluded_undeclared_vantage': [], 'out_of_scope_probes': 0, 'excess_reports': 0,
            'unparseable_reports': 0, 'oversize_reports': 0, 'stale_reports': 0,
            'blind': True, 'blind_reason': 'pending_batch'}


def tick(index_path: Path | str, config: Mapping[str, Any], cursor_path: Path | str,
         deliver: Callable[[dict[str, Any]], None], *, now: dt.datetime,
         source: str) -> dict[str, Any]:
    """Judge the reports, deliver what changed, and advance the cursor only after.

    One round, no loop, no client of its own: `deliver` is called once per event, so a round can fail
    between its first event and its second, or between its last event and the acknowledgement. That is
    why what it owes is written to the cursor **before** the first send and cleared only after the last
    one: the exact bytes, the condition state the round intends and the route state it computed ride out
    a crash and a lost ack alike. The platform folds a retry of identical bytes into the row it already
    holds, so replay is cheap and re-judging is not — a fresh healthy report cannot retroactively un-owe
    the `resolved` the failing round owed, and skipping the owed batch to judge the new one is how an
    incident stays open over a network the operator can see is healthy.

    So a round that finds a pending batch replays it and returns before reading anything (`_replay`),
    which is `conditions.tick`'s durability rule with one addition: this producer's round also carries
    route baselines, and a transition computed from a trace that has since moved is not the transition
    the failed round saw. Both halves of the intended final state travel with the batch.

    The undeclared-vantage check runs before a single report is read, and refuses the round: producer
    identity is not something a partial verdict may be built on — the same check `detections.evaluate`
    performs on a rule's resource, and the same reason. Reports whose own vantage does not resolve are
    dropped and counted instead, because that hole is what makes the verdict `indeterminate`, and a
    `blind` round (no readable, current report at all) is judged the same way — it is missing data,
    never a clean network.

    The cursor's parent is checked before anything is read: a round that judged, delivered and then
    found nowhere to remember the verdict by would have paged once per restart, and the refusal is
    cheaper to raise first than to explain afterwards.

    The summary carries the window, the verdict and its notes, the events delivered, the probe counts,
    the excluded/unparseable/stale counts, the route findings, the blank `(target, vantage)` pairs the
    verdict was degraded for and which condition is open now. A replay round reports no verdict — its
    `verdict` is null, its `window` is the one the replayed bytes carry, its `blind_reason` is
    `pending_batch` — because the true sentence about that round is that nothing was looked at. Nothing
    in any of it holds a credential; hop addresses appear only as digests.
    """
    path = Path(cursor_path)
    if not path.parent.is_dir():
        raise ValueError('Pathcheck cursor parent does not exist; create it before the first round')
    cursor = load_cursor(path, config)
    if cursor['pending']:
        return _replay(path, cursor, deliver)
    window = _window(now, int(config['interval_seconds']))
    end = timestamp(window['end'])
    settled = _settled_end(cursor)
    if settled is not None and end <= settled:
        return {'result': 'idle', 'window': window, 'verdict': None,
                'affected': [], 'failing': [], 'coverage_gaps': [], 'replayed_events': 0,
                'notes': ['This window was already completed; no reports were read.'],
                'events': [], 'open_finding': cursor['open'], 'observations': 0,
                'probes_by_vantage': {}, 'traces': 0, 'route_findings': [], 'latency': [],
                'latency_rows': 0, 'latency_truncated': False, 'transitions': 0,
                'excluded_undeclared_vantage': [], 'out_of_scope_probes': 0, 'excess_reports': 0,
                'unparseable_reports': 0, 'oversize_reports': 0, 'stale_reports': 0,
                'blind': False, 'blind_reason': 'settled_window'}
    with index.readonly(index_path) as connection:
        if index.resolve(connection, resource_id=config['vantage_resource_id'])['status'] != 'resolved':
            raise ValueError('Vantage point is not declared')
        read = load_reports(config['sources']['reports_dir'], protocols=config['protocols'], before=end)
        declared, undeclared = [], []
        for report in read['reports']:
            status = index.resolve(connection, resource_id=report.vantage_resource_id)['status']
            (declared if status == 'resolved' else undeclared).append(report)
    # The expected set is who *this* process is configured to be. A sibling vantage appearing or not in
    # the shared directory is not a promise this configuration can make, so its absence is simply not
    # expected; its presence only ever corroborates. That asymmetry is why one process per vantage.
    observations = [item for report in declared for item in report.observations]
    traces = [trace for report in declared for trace in report.traces]
    # The latency rows are the ping parser's output, and they are the only place a round says
    # "how badly" rather than "whether": 64 rows, then a count, because a probe runner can write
    # hundreds of series and the round's summary is a log line and a CLI field, not a table.
    series = [item for report in declared for item in report.latency]
    latency_rows = [{'vantage_resource_id': item.vantage_resource_id, 'target': item.target,
                     'protocol': item.protocol, 'sent': item.sent, 'received': item.received,
                     'loss_pct': round(item.loss_pct, 3), 'latency_avg_ms': item.latency_avg_ms,
                     'jitter_ms': item.jitter_ms, 'note': item.note}
                    for item in series[:MAX_LATENCY_ROWS]]
    if observations:
        verdict = classify(observations, expected_vantage_points=[config['vantage_resource_id']],
                           expected_targets=config['targets'])
    else:
        notes = [f'no probe report is current ({read["reason"] or "no reports read"}); the verdict '
                 'could not be computed']
        if undeclared:
            notes.append(f'{len(undeclared)} report(s) named a vantage point that is not declared; '
                         'their probes were excluded')
        notes.append('bgp feed absent: verdict derived from probe data alone (degraded)')
        verdict = ReachabilityVerdict(VERDICT_INDETERMINATE, (), (), tuple(notes))
    events, open_finding = verdict_findings(verdict, source=source,
                                            vantage_resource_id=config['vantage_resource_id'],
                                            window=window, observations=observations,
                                            open_finding=cursor['open'])
    # A copy, so the cursor keeps the state the last *completed* round reached while this round's is
    # still only intended: `observe_routes` writes its transitions into what it is handed, and a refused
    # batch must leave the route baselines where they were for the next round to recompute honestly.
    routes = dict(cursor['routes'])
    route_findings = observe_routes(routes, traces, observed_at=window['end'])
    if events:
        # Write down what this round owes before a single byte of it leaves. Everything after this line
        # is allowed to fail: the batch, the condition state it implies and the route state it computed
        # are on disk, and the next round's job is to send them, not to guess them again.
        save_cursor(path, _cursor_document(cursor, pending={
            'binding': cursor['binding'], 'end': window['end'], 'events': events,
            'open': open_finding, 'routes': routes}))
    for item in events:
        deliver(item)
    save_cursor(path, _cursor_document(cursor, state={'open': open_finding, 'routes': routes},
                                      settled_end=window['end']))
    return {'result': ('blind' if read['blind'] else 'delivered' if events else 'idle'),
            'window': window, 'verdict': verdict.verdict, 'affected': list(verdict.affected),
            'failing': [[target, vantage] for target, vantage in verdict.failing],
            'coverage_gaps': [[target, vantage] for target, vantage in verdict.coverage_gaps],
            'replayed_events': 0,
            'notes': list(verdict.notes), 'events': events,
            'open_finding': open_finding, 'observations': len(observations),
            'probes_by_vantage': {report.vantage_resource_id: len(report.observations)
                                  for report in declared},
            'traces': len(traces), 'route_findings': [item.as_dict() for item in route_findings],
            'latency': latency_rows, 'latency_rows': len(series),
            'latency_truncated': len(series) > MAX_LATENCY_ROWS,
            'transitions': sum(1 for item in route_findings
                               if item.transition in ('opened', 'resolved')),
            'excluded_undeclared_vantage': sorted({item.vantage_resource_id for item in undeclared}),
            'out_of_scope_probes': read['out_of_scope'], 'excess_reports': read['excess'],
            'unparseable_reports': read['unparseable'], 'oversize_reports': read['oversize'],
            'stale_reports': read['stale'], 'blind': read['blind'], 'blind_reason': read['reason']}


def main() -> int:
    """Run the producer loop; exit 0 without touching the network when nothing is configured.

    Identity comes from ``LO_PATHCHECK_SOURCE`` and must match the producer token's identity, since
    the platform records who said it; the index the vantage point is resolved against is
    ``LO_INDEX_PATH``, the same built snapshot every other reader here opens. Each round logs one INFO
    line naming the verdict, and a failed round logs a WARNING naming the error class, so a silent
    process is a process that is not running rather than a healthy one with nothing to say. This
    worker neither reads nor writes a notification mode: the delivery decision belongs to the platform
    service, as it does for a Gatus result or a drift report.
    """
    try:
        config = producer_config()
        if config is None:
            return 0
        allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=allow_http)
        index_path, source = os.environ['LO_INDEX_PATH'], os.environ[SOURCE_ENVIRONMENT]
        label(source)
        cursor = Path(config['cursor'])
        if not cursor.parent.is_dir():
            raise ValueError('Pathcheck cursor parent does not exist; create it before starting')
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        log.warning('Pathcheck producer cannot start; configuration is missing or invalid',
                    extra={'error_class': type(exc).__name__})
        return 1

    def deliver(item: dict[str, Any]) -> None:
        # Both a transport failure and a refused event leave the whole batch pending. Earlier
        # accepted events will replay as duplicates; a persistent refusal needs operator correction.
        status = platform.request('POST', '/v1/events', item)[0]
        if status != 200:
            raise PathCheckError(f'Pathcheck intake answered {status}; the batch remains pending')

    log.info('Pathcheck producer started', extra={'targets': len(config['targets']),
                                                  'tick_seconds': config['interval_seconds']})
    with exclusive_owner(cursor):
        while True:
            try:
                summary = tick(index_path, config, cursor, deliver, now=dt.datetime.now(dt.timezone.utc),
                               source=source)
                log.info('Pathcheck tick finished',
                         extra={'result': summary['result'], 'verdict': summary['verdict'],
                                'events': len(summary['events']), 'observations': summary['observations'],
                                'replayed_events': summary['replayed_events'],
                                'coverage_gaps': len(summary['coverage_gaps']),
                                'route_findings': len(summary['route_findings'])})
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                # sqlite3.Error because a round opens the inventory index, whose absence or damage
                # surfaces as an OperationalError, which is not an OSError: uncaught here it would end
                # the loop and let the service manager restart-loop on a missing mount.
                log.warning('Pathcheck delivery unavailable; cursor not advanced, this round repeats',
                            extra={'error_class': type(exc).__name__})
                log.debug('Pathcheck tick failed', exc_info=True)
            time.sleep(config['interval_seconds'])


if __name__ == '__main__':
    raise SystemExit(main())
