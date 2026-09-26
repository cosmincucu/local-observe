"""Bounded human notification text; stdlib-only so independent witnesses can reuse it.

Durable IDs remain in delivery envelopes and audit records. They are never a label
fallback. This formatter deliberately ignores evidence bodies and arbitrary event text.

The first line names who is affected — the monitored resource and its host, or an explicit
gap when no human label exists — so a phone notification is actionable before it is opened.
"""
import re
from typing import Any
from urllib.parse import urlsplit

UUID = re.compile(r'(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
                  r'|(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])')

#: Placeholder texts `presentation.describe` yields when inventory holds no usable name. They stay
#: valid body text but are never echoed as the headline subject: an inventory error is not a service.
RESOURCE_GAPS = frozenset({'Unassigned resource', 'Unnamed resource', 'Undeclared resource',
                           'Inventory unavailable'})
HOST_GAPS = frozenset({'Not declared', 'Unknown', 'Unnamed host'})


def _is_label(value: Any) -> bool:
    """Return whether `value` is a human label `human_text` would accept (never a durable ID)."""
    return isinstance(value, str) and bool(value.strip()) and not UUID.search(value)


def human_text(value: Any, fallback: str) -> str:
    """Accept a short presentation label, refusing UUIDs and empty/non-text values."""
    if not isinstance(value, str) or not value.strip() or UUID.search(value):
        return fallback
    return ' '.join(value.split())[:160]


def operations_url(value: Any) -> str | None:
    """Only an explicitly configured HTTPS console address may become an alert link."""
    if (not isinstance(value, str) or len(value) > 256
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        return None
    try:
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.port == 0
                or not re.fullmatch(r'[A-Za-z0-9.-]+', url.hostname)
                or not re.fullmatch(r'[A-Za-z0-9/._~-]*', url.path)):
            return None
    except ValueError:
        return None
    return value


def notification_lines(payload: dict[str, Any], display: dict[str, Any],
                       config: dict[str, Any] | None = None) -> list[str]:
    """Render labels from presentation/config, never raw event evidence or identity fields."""
    config = config if isinstance(config, dict) else {}
    payload = payload if isinstance(payload, dict) else {}
    display = display if isinstance(display, dict) else {}
    event = payload.get('event')
    event = event if isinstance(event, dict) else {}
    kind = event.get('kind')
    kind = kind if isinstance(kind, str) else None
    recovered = payload.get('transition') == 'resolved'
    prefix = human_text(config.get('message_prefix'), '[local-observe]')
    defaults = {'availability': 'Availability check failed', 'coverage': 'Monitoring data missing',
                'threshold': 'Detection threshold exceeded', 'drift': 'Inventory drift detected',
                'anomaly': 'Value outside its seasonal baseline', 'security': 'Security rule matched'}
    description = human_text(display.get('description'), defaults.get(kind, 'Monitoring incident'))
    if description == 'Monitoring incident':
        description = defaults.get(kind, description)
    resource = human_text(display.get('resource_name'), 'Resource not identified')
    host = human_text(display.get('host_name'), 'Host not identified')
    resource_named = _is_label(display.get('resource_name')) and resource not in RESOURCE_GAPS
    host_named = _is_label(display.get('host_name')) and host not in HOST_GAPS
    if resource in ('Unassigned resource', 'Unnamed resource', 'Undeclared resource'):
        resource = 'Resource label unavailable'
    if host in ('Not declared', 'Unknown'):
        host = 'Host not identified'
    if not event.get('resource_id'):
        resource = human_text(config.get('witness_resource'), 'local-observe platform')
        host = human_text(config.get('witness_host'), 'Host not configured')
        resource_named = _is_label(config.get('witness_resource'))
        host_named = _is_label(config.get('witness_host'))
        if description == 'Monitoring incident':
            description = 'Platform availability check'
    channel = human_text(config.get('channel_name'), 'Notifications')
    console = operations_url(config.get('operations_url'))
    if recovered:
        next_step = 'Review the incident and confirm recent checks remain healthy.'
    else:
        next_step = 'Open Operations; inspect the incident and recent checks before taking action.'
    if console:
        next_step = ('Review recovery in Operations: ' if recovered
                     else 'Inspect the incident in Operations: ') + console
    if not event.get('resource_id'):
        next_step = ('Confirm platform availability; review witness logs if the alert repeats.' if recovered
                     else 'Check platform availability and the external witness logs.')
        if console:
            next_step = ('Confirm Operations is reachable: ' if recovered
                         else 'Check Operations availability: ') + console
    headline = prefix + (' RECOVERED' if recovered else ' ALERT')
    # Every headline identifies both subjects or states the missing labels.
    # Labels and prefix have already passed the same 160-character bound.
    headline += ' — ' + ((resource if resource_named else 'resource label missing')
                         + ' @ ' + (host if host_named else 'host label missing'))
    return [headline,
            'Incident: ' + description, 'Resource: ' + resource, 'Host: ' + host,
            'Condition: ' + ('Recovered' if recovered else 'Active'),
            'Delivery: ' + channel, 'Next: ' + next_step]
