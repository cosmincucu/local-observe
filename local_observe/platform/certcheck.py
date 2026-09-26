"""Certificate verdicts from injected facts and an aware clock; never opens a socket.

Gatus owns HTTP/DNS/TLS probing and API checks (gatus for synthetics); their old engines are
not ported. Browser transactions are excluded by dead code. This helper adds named
chain/hostname verdicts and stable staged expiry conditions, not a TLS client.
"""
from dataclasses import dataclass
import datetime as dt
import ipaddress
import re
from collections.abc import Callable

from local_observe.inventory.validation import digest, timestamp, utc_text
from .assertions import safe_name
from .detections import event
from .state import StateError, identifier, label, validate_event
from . import vocabulary

DEFAULT_THRESHOLDS = (30, 14, 3)


@dataclass(frozen=True)
class CertFacts:
    not_after: str
    chain_valid: bool
    sans: list[str]


@dataclass(frozen=True)
class CertResult:
    ok: bool
    days_to_expiry: float | None
    samples: list[dict]
    events: list[dict]
    error: str | None = None


def _dns_name(value: str) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 253
            and all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', part)
                    for part in value.rstrip('.').split('.')))


def hostname_matches(host: str, sans: list[str]) -> bool:
    """Exact DNS/IP SAN or one leftmost wildcard DNS label; no broad substring match."""
    host = host.lower().rstrip('.')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for san in sans:
        pattern = san.lower().rstrip('.')
        if address is not None:
            try:
                if ipaddress.ip_address(pattern) == address:
                    return True
            except ValueError:
                continue
        elif pattern == host or (pattern.startswith('*.') and '.' in host
                                 and host.split('.', 1)[1] == pattern[2:]):
            return True
    return False


def run_cert_check(rule_id: str, resource_id: str, host: str,
                   fetcher: Callable[[str, int], CertFacts], *, clock: Callable[[], dt.datetime],
                   source: str = 'synthetics.tls', port: int = 443,
                   thresholds: tuple[int, ...] = DEFAULT_THRESHOLDS) -> CertResult:
    """Return evidence before events for the caller to durably batch and deliver.

    Missing/malformed facts produce only fetch-error coverage, no gauge and no
    recovery. A fully healthy certificate outside all stages resolves each stage.
    Within a stage only the tightest crossed expiry condition fires.
    """
    safe_name(rule_id)
    identifier(resource_id)
    label(source)
    if (not isinstance(thresholds, (list, tuple)) or not 1 <= len(thresholds) <= 16
            or any(type(value) is not int or not 1 <= value <= 36500 for value in thresholds)
            or list(thresholds) != sorted(set(thresholds), reverse=True)):
        raise StateError('Invalid descending certificate thresholds')
    if type(port) is not int or not 1 <= port <= 65535:
        raise StateError('Invalid certificate port')
    try:
        valid_host = isinstance(host, str) and bool(ipaddress.ip_address(host))
    except ValueError:
        valid_host = _dns_name(host)
    if not valid_host or not callable(fetcher) or not callable(clock):
        raise StateError('Invalid certificate configuration')
    now = clock()
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise StateError('Certificate clock must be timezone aware')
    now = now.astimezone(dt.timezone.utc)
    observed = utc_text(now)
    window = {'start': utc_text(now - dt.timedelta(seconds=60)), 'end': observed}

    def emit(suffix, status, *, kind='availability', sample=None, severity=None):
        name = rule_id + '.' + suffix
        parameters = {'rule_id': name}
        if sample is not None:
            parameters['sample_id'] = sample['sample_id']
        item = event(source, resource_id, name, kind, status, window, parameters,
                     query_type='source-heartbeat' if kind == 'coverage' else 'gatus-result',
                     severity=severity)
        validate_event(item, now)
        return item

    try:
        facts = fetcher(host, port)
        if (not isinstance(facts, CertFacts) or type(facts.chain_valid) is not bool
                or not isinstance(facts.not_after, str) or not 1 <= len(facts.not_after) <= 64
                or not isinstance(facts.sans, list) or len(facts.sans) > 100):
            raise ValueError('Invalid certificate facts')
        for san in facts.sans:
            if not isinstance(san, str):
                raise ValueError('Invalid certificate SAN')
            try:
                ipaddress.ip_address(san)
            except ValueError:
                if not _dns_name(san[2:] if san.startswith('*.') else san):
                    raise ValueError('Invalid certificate SAN') from None
        expires = timestamp(facts.not_after)
        days = (expires - now).total_seconds() / 86400
    except Exception:  # Injected measurement failure; never persist exception text or fabricated days.
        return CertResult(False, None, [], [emit('fetch-error', 'firing', kind='coverage')], 'fetch-error')

    def sample(name, value):
        result = {'observed_at': observed, 'ok': True, 'value': value}
        result['sample_id'] = digest([source, resource_id, rule_id, name, result])
        return result

    gauge = sample('days-to-expiry', days)
    chain = sample('chain-valid', facts.chain_valid)
    hostname = sample('hostname-matches-san', hostname_matches(host, facts.sans))
    events = [emit('fetch-error', 'resolved', kind='coverage', sample=gauge)]
    for suffix, measured in [('chain-valid', chain), ('hostname-matches-san', hostname)]:
        events.append(emit(suffix, 'resolved' if measured['value'] else 'firing', sample=measured))
    crossed = [threshold for threshold in thresholds if days <= threshold]
    if crossed:
        stage = min(crossed)
        # Cite the central source ladder: its first rung is the tightest stage's severity.
        tier = 0 if stage == thresholds[-1] else 1 if stage != thresholds[0] else 2
        severity = vocabulary.severity('core-events-v1',
                                       vocabulary.SOURCE_VOCABULARIES['core-events-v1'].severities[tier])
        events.append(emit(f'expiry-{stage}d', 'firing', sample=gauge, severity=severity))
    elif chain['value'] and hostname['value']:
        events.extend(emit(f'expiry-{stage}d', 'resolved', sample=gauge) for stage in thresholds)
    return CertResult(bool(chain['value'] and hostname['value'] and not crossed), days,
                      [gauge, chain, hostname], events)
