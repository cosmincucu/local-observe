"""Durable notification budgets, synthetic routing and a latched flood breaker.

Control state lives in its own tables (schema v2, ledger control state): `notification_control` for the
delivery mode, one flood breaker per channel and one approved test window per id, `notification_reservations`
for the send slots already taken and `notification_suppressions` for deliveries that may never be
sent. All of them are written in the same transaction as the outbox claim, beside the audit rows that
stay the history of those decisions. A crash consumes a slot, never creates a free send.

Every budget, breaker and slot here is already per channel; since schema v3 (ledger notifications) a store may
be configured with more than one, and `reserve_route` is what walks them in the operator's order.
"""
from dataclasses import dataclass, field
import datetime as dt
import json
import sqlite3
from typing import Any

from local_observe.inventory.validation import canonical, timestamp, utc_text
from .state import (StateError, Store, circuit_key, control_read, control_write, label,
                    record_reservation, test_window_key)

SAFETY_CONTRACT = 2
# The two states of a channel's flood breaker, as stored under `circuit:<channel>`.
CIRCUIT_OPEN = 'open'
CIRCUIT_CLOSED = 'closed'
# The destination a refusal names when no slot was ever taken: a refusal is always about the human channel.
HUMAN_DESTINATION = 'human'


@dataclass(frozen=True)
class NotificationPolicy:
    channel: str = 'primary'
    max_attempts: int = 10
    window_seconds: int = 600
    max_event_age_seconds: int = 900
    synthetic_sources: tuple = ()
    test_window: dict | None = field(default=None)
    delivery_mode: str = 'recording'

    def __post_init__(self):
        if self.delivery_mode not in ('off', 'recording', 'live'):
            raise StateError('Notification mode must be off, recording or live')
        if self.delivery_mode != 'live' and self.test_window is not None:
            raise StateError('Human-channel test windows require live notification mode')
        label(self.channel)
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100:
            raise StateError('Notification budget must be 1..100 attempts')
        if type(self.window_seconds) is not int or not 60 <= self.window_seconds <= 86400:
            raise StateError('Notification rate window must be 60..86400 seconds')
        if type(self.max_event_age_seconds) is not int or not 60 <= self.max_event_age_seconds <= 86400:
            raise StateError('Notification event age must be 60..86400 seconds')
        for source in self.synthetic_sources:
            label(source)
        if self.test_window is not None:
            w = self.test_window
            if set(w) != {'id', 'starts_at', 'expires_at', 'max_attempts'}:
                raise StateError('An explicit bounded human-channel test window is required')
            label(w['id'])
            if not dt.timedelta(0) < timestamp(w['expires_at']) - timestamp(w['starts_at']) <= dt.timedelta(minutes=10):
                raise StateError('Human-channel test window must expire within ten minutes')
            if type(w['max_attempts']) is not int or not 1 <= w['max_attempts'] <= 10:
                raise StateError('Human-channel test budget must be 1..10 attempts')

    def synthetic(self, event: dict[str, Any]) -> bool:
        # stage-* is reserved for non-production producers, even without an overlay.
        return event['source'].startswith('stage-') or event['source'] in self.synthetic_sources


def circuit_state(db: sqlite3.Connection, channel: str) -> dict:
    """Return one channel's flood breaker: its state, when it changed, and where the budget counts from.

    A channel that never latched reads as closed with no reset boundary, which is what an absent
    `circuit:<channel>` row means. `reset_at` is the instant of the last human reset and the start of
    the send budget: slots taken before it are excluded from the window count (ledger control state).
    """
    stored = control_read(db, circuit_key(channel))
    if not stored:
        return {'state': CIRCUIT_CLOSED, 'at': '', 'reset_at': ''}
    try:
        record = json.loads(stored)
    except ValueError:
        record = None
    if not isinstance(record, dict):
        # Anything this build cannot read stays latched: an unparseable breaker is the refusal-prone
        # answer, and with no reset instant the window count ages on its own rather than restarting.
        return {'state': CIRCUIT_OPEN, 'at': '', 'reset_at': ''}
    return {'state': CIRCUIT_CLOSED if record.get('state') == CIRCUIT_CLOSED else CIRCUIT_OPEN,
            'at': record.get('at') or '', 'reset_at': record.get('reset_at') or ''}


def circuit(db: sqlite3.Connection, channel: str) -> bool:
    """Return True while the flood breaker of `channel` is latched open and refuses every human send."""
    return circuit_state(db, channel)['state'] == CIRCUIT_OPEN


def _write_circuit(db: sqlite3.Connection, channel: str, state: str, reset_at: str, now: dt.datetime) -> None:
    """Store one breaker transition, keeping the reset boundary the budget window is counted from."""
    control_write(db, circuit_key(channel),
                  canonical({'at': utc_text(now), 'reset_at': reset_at, 'state': state}), now)


def latch_circuit(db: sqlite3.Connection, channel: str, now: dt.datetime) -> None:
    """Latch the flood breaker open until a human resets it, leaving any earlier reset instant alone."""
    _write_circuit(db, channel, CIRCUIT_OPEN, circuit_state(db, channel)['reset_at'], now)


def reset_circuit(db: sqlite3.Connection, channel: str, now: dt.datetime) -> None:
    """Unlatch the breaker and start the send budget again at this instant.

    The instant is what makes a reset buy something: without it the slots that tripped the breaker are
    still inside the window and the next send re-latches it, which is the behaviour regression tests could only
    document (`tests/test_regression_timing.py`) and control state decided against.
    """
    _write_circuit(db, channel, CIRCUIT_CLOSED, utc_text(now), now)


def _window_start(now: dt.datetime, reset_at: str, window_seconds: int) -> dt.datetime:
    """Return the instant to count send slots from: the later of the ageing window and the last reset.

    The reset wins when it is more recent, which is what excludes the slots a human has just
    reconciled. A reset instant this build cannot read is ignored, and the window ages on its own —
    the choice that keeps counting slots rather than the one that hands them out.
    """
    start = now - dt.timedelta(seconds=window_seconds)
    if not reset_at:
        return start
    try:
        return max(start, timestamp(reset_at))
    except ValueError:
        return start


def _reserve_slot(store, db: sqlite3.Connection, outbox_id: str, detail: dict, now: dt.datetime) -> None:
    """Take one send slot in both places it belongs: the durable budget table and the audit log."""
    store.audit(db, now, 'notification-worker', 'notification.reserved', outbox_id, detail)
    record_reservation(db, outbox_id, detail, now)


def reserve(store: Store, db: sqlite3.Connection, row: sqlite3.Row, policy: NotificationPolicy,
            now: dt.datetime) -> tuple[dict[str, Any], str | None]:
    """Decide one queued delivery and, when it may be sent, take its slot in the caller's transaction.

    Returns the route (channel, destination, test window) and the reason the delivery is suppressed, or
    None when it may go. Every count here is a query over `notification_reservations`, never over the
    audit log, so a change to an audit `detail` layout cannot change delivery behaviour.
    """
    event = json.loads(row['payload'])['event']
    detail = {'channel': policy.channel, 'destination': HUMAN_DESTINATION, 'test_window': None}
    if policy.delivery_mode == 'off':
        return detail, 'notifications-disabled'
    if event['data_class'] == 'restricted':
        return detail, 'restricted-channel-policy-required'
    if (now - timestamp(event['observed_at'])).total_seconds() > policy.max_event_age_seconds:
        return detail, 'event-too-old'
    if policy.delivery_mode == 'recording':
        detail['destination'] = 'recording-sink'
        _reserve_slot(store, db, row['id'], detail, now)
        return detail, None
    if policy.synthetic(event):
        if policy.test_window is None:
            detail['destination'] = 'synthetic-sink'
            _reserve_slot(store, db, row['id'], detail, now)
            return detail, None
        w = policy.test_window
        detail['test_window'] = w['id']
        previous = control_read(db, test_window_key(w['id']))
        if previous and previous != canonical(w):
            return detail, 'test-window-definition-changed'
        if not previous:
            control_write(db, test_window_key(w['id']), canonical(w), now)
            store.audit(db, now, 'notification-worker', 'notification.test_window', w['id'], w)
        start, expiry = timestamp(w['starts_at']), timestamp(w['expires_at'])
        if not start <= now < expiry or not start <= timestamp(event['observed_at']) < expiry:
            return detail, 'test-window-inactive-or-old-event'
        # A window ID cannot gain slots by restarting or editing its timestamps.
        count = db.execute('SELECT count(*) FROM notification_reservations WHERE test_window=?',
                           (w['id'],)).fetchone()[0]
        if count >= w['max_attempts']:
            return detail, 'test-budget-exhausted'
    breaker = circuit_state(db, policy.channel)
    if breaker['state'] == CIRCUIT_OPEN:
        return detail, 'flood-circuit-open'
    count = db.execute("""SELECT count(*) FROM notification_reservations
        WHERE channel=? AND destination='human' AND julianday(at)>julianday(?)""",
        (policy.channel, utc_text(_window_start(now, breaker['reset_at'], policy.window_seconds)))).fetchone()[0]
    if count >= policy.max_attempts:
        store.audit(db, now, 'notification-worker', 'notification.circuit_open', policy.channel,
                    {'reason': 'attempt-budget-exhausted'})
        latch_circuit(db, policy.channel, now)
        return detail, 'flood-circuit-open'
    _reserve_slot(store, db, row['id'], detail, now)
    return detail, None


def reserve_route(store, db: sqlite3.Connection, row: sqlite3.Row, policies: dict[str, NotificationPolicy],
                  now: dt.datetime) -> tuple[dict[str, Any], str | None]:
    """Choose the channel one queued delivery goes out on, trying each configured one in order.

    This is the multi-channel wrapper around `reserve` (ledger notifications): the order of `policies` is the
    operator's preference, the first channel whose policy admits the delivery takes it, and a channel
    that refuses is passed over rather than ending the decision. So a latched breaker on one channel is
    exactly what it should be — that channel stops sending — and the delivery goes to whichever channel
    still has budget, because `reserve` counts slots, and latches breakers, per channel.

    When no channel admits the delivery the answer is the refusal raised by the *first* one tried. That
    is deliberate: today's deployments have exactly one channel, and their suppression reasons stay
    byte-identical; and every reason that is not about a channel's own health (`event-too-old`,
    `restricted-channel-policy-required`, `notifications-disabled`) is raised identically by all of them
    anyway, so the first is not an arbitrary pick among different answers.

    Returns:
        The route (channel, destination, test window) of the channel that took the delivery — its slot is
        already recorded in the caller's transaction — and the refusal reason, or None when it may go.
    """
    first: tuple[dict[str, Any], str] | None = None
    for policy in policies.values():
        route, reason = reserve(store, db, row, policy, now)
        if not reason:
            return route, None
        if first is None:
            first = (route, reason)
    if first is None:
        # `Store.__init__` always files the store's own policy under its own channel, so an empty set
        # means a caller built the mapping by hand and left it blank. Refusing is the honest answer:
        # claiming a suppression reason for a channel that does not exist would invent a decision.
        raise StateError('No notification channel is configured')
    return first


class RecordingSink:
    """No network: the outbox payload and sink receipt are the durable test record."""
    def request(self, method: str, *, payload: dict[str, Any],
                headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}
