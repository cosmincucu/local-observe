"""Ping and traceroute analysis over **injected** probe series: no process is ever spawned here.

path monitoring ports the two v0.1 parsers — `legacy:netpath/ping.py` (126 lines) and `legacy:netpath/traceroute.py`
(180 lines). Both were already process-free in v0.1 and both stay process-free here: `mtr`,
`traceroute` and `fping` are **adopted external engines, never children of this process** (port
table §6, `netpath` row: "— (`mtr`/`fping`/bgpalerter adopted, never spawned)"). What the product
ships is the analysis of what such an engine printed, taken as a JSON report the operator's own job
writes; `pathcheck.py` documents its source and deployment boundary: the probe
runner is operator-side content, and `docs/COMPONENTS.md` §3 excludes a hosted probe service from
this product). No `subprocess`, no `Popen`, no shell, no binary on `PATH`.

Two reasons the seam is worth keeping rather than wiring a probe in:

* **A process is not evidence.** `docs/CONTRACTS.md` §4 makes an evidence reference something the
  platform can reauthorise later, and "whatever ``mtr`` printed on that host under whatever
  ``/etc/hosts``" is not reauthorisable by anything. What is reauthorisable is the injected series:
  the same list of RTTs produces the same report on any host, in any test tier, with no capability
  granted to the process that computed it.
* **The vantage points are the point.** This module's verdict only matters across several vantage
  points, so the caller is by construction somewhere other than the probe host, and the transport
  in between is the operator's to choose (a copy job, a mount, a POST to something that files
  reports). Choosing that transport is not this module's call, and every argument it takes is a
  value the caller already holds.

What the port changes, deliberately:

* **A vantage point is a declared resource, not a label.** v0.1's functions took a free-text
  `vantage_point` string; these take `vantage_resource_id`, a canonical UUID, and refuse anything
  else. A probe host with no declared identity has no right to a verdict (§6 delta, task 5), and a
  UUID is what lets `pathcheck.classify` be checked against the inventory index before a verdict is
  filed. The identity check lives here as well as in `pathcheck.py` so a parser cannot be handed a
  label that never resolves and then feed a verdict built on it.
* **Unmeasured is not zero.** An all-lost series answers `None` for every latency field *and*
  carries the reason in `note` — v0.1's stance, kept exactly (its testing-standards rule 4: an
  unmeasured value is never fabricated). A caller that wants a number out of `None` has to say so.
* **Every bound is a refusal at the door.** v0.1 checked a type here and there and trusted the rest;
  here the series length, the hop count, the millisecond range, the address charset and the label
  shape are all refused before a report exists, because the input arrives from a file another
  process wrote and a report built over `1e308` ms or a 100 000-hop trace is a report about nothing.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from local_observe.inventory.validation import digest

#: The three probe protocols a vantage point may speak. Kept as a closed set (v0.1's `PROTOCOLS`) so
#: a report naming `"http"` refuses here instead of producing a report that reads like the others.
PROTOCOLS = ('icmp', 'tcp', 'udp')
#: Samples per probe, and hops per trace. Both are ceilings on an injected list, not a policy about
#: how often to probe: a series longer than this cannot have come from one interval of one probe.
MAX_SERIES = 256
MAX_HOPS = 64
#: One RTT, in milliseconds. The ceiling is a day in milliseconds: an RTT above it is a lost probe
#: recorded wrongly, and a report built on one would put the mean anywhere the caller likes.
MAX_RTT_MS = 86_400_000.0
#: The address an unresponsive hop is recorded as (a router that never replies prints no address). It
#: counts toward the path
#: signature on purpose: a hop flapping between replying and not replying IS a visible path change
#: and must never be smoothed over into "same path, one quiet router".
UNRESPONSIVE_HOP = '*'
# Restated byte-for-byte from `state.label` / `inventory/schemas/common.json` rather than imported:
# `store/client.py` sets the precedent that a bounded name check must not drag in the platform's
# SQLite layer (or an inventory import) just to reject a string. A target name is operator-typed
# text from a report file, and it must not be able to carry a path, a URL or a log-line break.
LABEL = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
# The canonical UUID form `inventory/schemas/common.json#/$defs/uuid` admits — lowercase, hyphenated.
RESOURCE_ID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
# A hop address: an IPv4/IPv6 literal or a hostname, and nothing else. No slash, no space, no
# control character, so a hop list cannot forge a line in the producer's own log output.
HOP_ADDRESS = re.compile(r'[A-Za-z0-9_.:-]{1,64}')
_JITTER_MIN_REPLIES = 2


class PathParseError(ValueError):
    """A probe report could not be analyzed. Every message names the field, never the payload."""


def _resource(value: Any) -> str:
    """Return *value* as a canonical declared resource id, refusing a label or a shaped-alike."""
    if not isinstance(value, str) or not RESOURCE_ID.fullmatch(value):
        raise PathParseError('vantage_resource_id must be a canonical declared UUID')
    return value


def _name(value: Any, field: str) -> str:
    """Return *value* as a bounded target label; a name is the only free-text field a report holds."""
    if not isinstance(value, str) or not LABEL.fullmatch(value):
        raise PathParseError(f'{field} must be a bounded label of 1-128 characters from [A-Za-z0-9_.:-]')
    return value


def require_protocol(protocol: Any) -> str:
    """Return *protocol* when it is one of :data:`PROTOCOLS`; refuse every other value.

    Shared by both parsers exactly as v0.1 shared it, so an ICMP run can never be compared with a
    TCP run under one key: a path change per `(vantage, target, protocol)` is only meaningful if the
    protocol is one of the three this product says a probe may speak.
    """
    if protocol not in PROTOCOLS:
        raise PathParseError(f'protocol must be one of {", ".join(PROTOCOLS)}')
    return protocol


def _bounded_rtt(value: Any, field: str) -> float | None:
    """Return *value* as a finite, non-negative millisecond RTT, or ``None`` for a lost probe.

    ``bool`` is refused before the numeric check because Python says ``True == 1``: a report that
    wrote `true` where a sample belonged would otherwise enter the mean as one millisecond, which is
    a fabricated measurement wearing the shape of data.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PathParseError(f'{field} must hold a number of milliseconds or null')
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= MAX_RTT_MS:
        raise PathParseError(f'{field} holds an RTT outside 0-{MAX_RTT_MS:g} ms')
    return number


def _series(values: Any, field: str) -> list[float | None]:
    """Return *values* as a non-empty bounded RTT series (`None` = lost probe)."""
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise PathParseError(f'{field} must be a list of numbers or null')
    if not 1 <= len(values) <= MAX_SERIES:
        raise PathParseError(f'{field} must hold 1-{MAX_SERIES} samples')
    return [_bounded_rtt(item, field) for item in values]


@dataclass(frozen=True)
class PingReport:
    """Per-`(vantage_resource_id, target, protocol)` latency, loss and availability.

    A ``None`` latency or jitter field means *unmeasured* — read :attr:`note` for why — and never
    means zero. :attr:`availability_pct` is reply-level (replies over sends); with one series it
    equals ``100 - loss_pct`` by construction, which is why both are kept: the two words mean
    different things the moment reports from two vantage points are compared.
    """
    vantage_resource_id: str
    target: str
    protocol: str
    sent: int
    received: int
    loss_pct: float
    latency_min_ms: float | None
    latency_avg_ms: float | None
    latency_max_ms: float | None
    jitter_ms: float | None
    availability_pct: float
    note: str


def analyze_ping(rtts_ms: Any, *, vantage_resource_id: Any, target: Any,
                 protocol: str = 'icmp') -> PingReport:
    """Analyze an injected per-probe RTT series (``None`` = a lost probe). Nothing is measured here.

    Jitter is the mean absolute difference between consecutive *received* RTTs — losses are skipped
    over, never read as a zero gap, which is v0.1's definition and the only one that does not turn a
    dropped packet into a claim about queueing. Fewer than two replies yield ``jitter_ms = None``
    with the reason in ``note``; zero replies yield every latency field as ``None`` with the reason.

    Raises:
        PathParseError: The series is empty, unbounded or holds a value that is not a non-negative
            finite number or ``None``, or a name/protocol is not one this product admits. An empty
            series raises rather than returning a zero-filled report: there is nothing to analyze and
            nothing may be fabricated.
    """
    samples = _series(rtts_ms, 'rtts_ms')
    resource = _resource(vantage_resource_id)
    name = _name(target, 'target')
    require_protocol(protocol)
    replies = [item for item in samples if item is not None]
    sent, received = len(samples), len(replies)
    loss_pct = 100.0 * (sent - received) / sent
    availability_pct = 100.0 * received / sent
    if received == 0:
        return PingReport(resource, name, protocol, sent, 0, loss_pct, None, None, None, None,
                          availability_pct, 'no replies received: latency/jitter unmeasured')
    if received < _JITTER_MIN_REPLIES:
        jitter: float | None = None
        note = f'jitter needs at least {_JITTER_MIN_REPLIES} replies, got {received}: jitter unmeasured'
    else:
        jitter = sum(abs(later - earlier) for earlier, later in zip(replies, replies[1:])) / (received - 1)
        note = ''
    return PingReport(resource, name, protocol, sent, received, loss_pct, min(replies),
                      sum(replies) / received, max(replies), jitter, availability_pct, note)


@dataclass(frozen=True)
class HopSeries:
    """One hop's latency/loss series. ``None`` statistics mean *no reply at this hop*, not zero.

    :attr:`address` is :data:`UNRESPONSIVE_HOP` when the hop never named itself, which is a fact
    about the path and not a gap in it: it is recorded, counted and part of the signature.
    """
    ttl: int
    address: str
    sent: int
    received: int
    loss_pct: float
    rtt_min_ms: float | None
    rtt_avg_ms: float | None
    rtt_max_ms: float | None
    rtts_ms: tuple[float | None, ...]


@dataclass(frozen=True)
class TraceReport:
    """One traceroute/MTR run from one vantage point to one target.

    :attr:`path` is the address sequence in TTL order and is what a path change is measured against;
    :attr:`path_signature` is its bounded digest, which is what a cursor may hold across a restart.
    """
    vantage_resource_id: str
    target: str
    protocol: str
    hops: tuple[HopSeries, ...]
    hop_count: int
    path: tuple[str, ...]
    path_signature: str


def parse_traceroute(raw_hops: Any, *, vantage_resource_id: Any, target: Any,
                     protocol: str = 'icmp') -> TraceReport:
    """Parse an injected hop set into per-hop series, a path and its signature.

    Each raw hop is a mapping with ``ttl`` (int ≥ 1), ``address`` (a bounded literal, or ``None``
    when the hop never replied) and ``rtts_ms`` (a non-empty bounded series). Hops are ordered by TTL
    and a duplicate TTL is a malformed run: two rows claiming TTL 7 cannot both be on the path, and
    reading one of them would invent a route.

    Raises:
        PathParseError: Any field of any hop is missing, out of range or of the wrong type, the set
            is empty or longer than :data:`MAX_HOPS`, or a name/protocol is refused.
    """
    resource = _resource(vantage_resource_id)
    name = _name(target, 'target')
    require_protocol(protocol)
    if isinstance(raw_hops, (str, bytes)) or not isinstance(raw_hops, (list, tuple)):
        raise PathParseError('hops must be a list of hop records')
    if not 1 <= len(raw_hops) <= MAX_HOPS:
        raise PathParseError(f'hops must hold 1-{MAX_HOPS} records')
    seen: set[int] = set()
    hops: list[HopSeries] = []
    for raw in raw_hops:
        if not isinstance(raw, dict) or set(raw) - {'ttl', 'address', 'rtts_ms'} or 'ttl' not in raw \
                or 'rtts_ms' not in raw:
            raise PathParseError('a hop record names ttl, rtts_ms and optionally address')
        ttl = raw['ttl']
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 255:
            raise PathParseError('hop ttl must be a whole number from 1 to 255')
        if ttl in seen:
            raise PathParseError(f'duplicate hop ttl {ttl}: malformed run')
        seen.add(ttl)
        address = raw.get('address')
        if address is None:
            address = UNRESPONSIVE_HOP
        elif not isinstance(address, str) or not HOP_ADDRESS.fullmatch(address):
            raise PathParseError('hop address must be a bounded IPv4/IPv6/hostname literal or null')
        samples = _series(raw['rtts_ms'], f'hop {ttl} rtts_ms')
        replies = [item for item in samples if item is not None]
        hops.append(HopSeries(ttl, address, len(samples), len(replies),
                              100.0 * (len(samples) - len(replies)) / len(samples),
                              min(replies) if replies else None,
                              sum(replies) / len(replies) if replies else None,
                              max(replies) if replies else None,
                              tuple(samples)))
    hops.sort(key=lambda item: item.ttl)
    path = tuple(item.address for item in hops)
    return TraceReport(resource, name, protocol, tuple(hops), len(hops), path,
                       path_signature(path))


def path_signature(path: Any) -> str:
    """Return the sha256 of a path's address sequence, as lowercase hex.

    The signature is what a cursor stores and compares: a hop list is unbounded text, a digest is
    64 characters, and a condition identity must survive the route it describes being renamed or
    reordered without carrying the route around in a state file. ``*`` participates on purpose, so
    an unresponsive hop moving in or out of the same position is a different signature.
    """
    if isinstance(path, str) or not isinstance(path, (list, tuple)):
        raise PathParseError('path must be a sequence of hop addresses')
    if not 1 <= len(path) <= MAX_HOPS:
        raise PathParseError(f'path must hold 1-{MAX_HOPS} hops')
    for item in path:
        if item != UNRESPONSIVE_HOP and (not isinstance(item, str) or not HOP_ADDRESS.fullmatch(item)):
            raise PathParseError('path entries must be bounded hop literals or the unresponsive mark')
    return digest(list(path))
