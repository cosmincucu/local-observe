"""Optional channel driver with an ephemeral process challenge and explicit OS reconciliation."""
from __future__ import annotations

import datetime as dt
import os
import secrets
import uuid
from dataclasses import fields as dataclass_fields
from typing import Protocol

from .acceptance import AcceptedQuality, channel_identity
from .contract import ObserverError, digest, encoded, fields, instant, require, strict_json, utc
from .environment import protected_json
from .telegram import Telegram, TelegramConfig


class Channel(Protocol):
    def arm_after_reconciliation(self, epoch: str, *, now, used_today_floor=None) -> None: ...
    def deliver(self, cycle_id: str, *, now: dt.datetime) -> dict: ...
    def poll_feedback(self, *, now: dt.datetime) -> dict: ...


def read_channel(path) -> TelegramConfig | None:
    value = protected_json(path)
    if isinstance(value, dict) and value.get('mode') == 'recording':
        fields(value, {'schema_version', 'mode'}, {'requested_channel', 'model_delivery_enabled'})
        require(type(value['schema_version']) is int and value['schema_version'] == 1
                and value.get('model_delivery_enabled', False) is False, 'invalid_recording_channel')
        return None
    allowed = {field.name for field in dataclass_fields(TelegramConfig)}
    fields(value, {'schema_version', 'mode', 'token_file', 'chat_id', 'user_id'},
           allowed - {'token_file', 'chat_id', 'user_id'})
    require(type(value['schema_version']) is int and value['schema_version'] == 1
            and value['mode'] == 'telegram', 'invalid_delivery_channel')
    return TelegramConfig(**{key: item for key, item in value.items() if key in allowed})


def _sessions(journal):
    with journal.db:
        journal.db.execute('CREATE TABLE IF NOT EXISTS observer_delivery_sessions '
                           '(session_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, document TEXT NOT NULL)')


def session_status(journal) -> dict:
    _sessions(journal)
    row = journal.db.execute('SELECT document FROM observer_delivery_sessions ORDER BY rowid DESC LIMIT 1').fetchone()
    return strict_json(row[0]) if row else {'state': 'no_running_session'}


def reconcile(journal, *, session_id: str, epoch: str, attested: bool, now: dt.datetime,
              used_today_floor: int | None = None) -> dict:
    require(attested is True, 'external_effect_reconciliation_required')
    try:
        require(str(uuid.UUID(epoch)) == epoch, 'fresh_delivery_epoch_required')
    except (ValueError, TypeError, AttributeError) as exc:
        raise ObserverError('fresh_delivery_epoch_required') from exc
    _sessions(journal)
    with journal.lock() as acquired:
        require(acquired, 'observer_busy')
        current = session_status(journal)
        require(current.get('session_id') == session_id and current.get('state') == 'waiting',
                'fresh_process_challenge_required')
        require(instant(current['created_at']) <= now < instant(current['expires_at']), 'reconciliation_expired')
        old = journal.db.execute('SELECT epoch FROM observer_delivery_control WHERE singleton=1').fetchone()
        require(old is None or old[0] != epoch, 'fresh_delivery_epoch_required')
        require(used_today_floor is None or type(used_today_floor) is int and 0 <= used_today_floor <= 2,
                'invalid_reconciled_spend')
        current.update(state='authorized', epoch=epoch, actor=f'os-uid:{os.getuid()}', reconciled_at=utc(now),
                       used_today_floor=used_today_floor)
        with journal.db:
            journal.db.execute('UPDATE observer_delivery_sessions SET document=? WHERE session_id=?',
                                (encoded(current), session_id))
    return current


def disarm(journal, *, now) -> dict:
    _sessions(journal)
    with journal.lock() as acquired:
        require(acquired, 'observer_busy')
        current = session_status(journal)
        if 'session_id' in current:
            current.update(state='disarmed', disarmed_at=utc(now), actor=f'os-uid:{os.getuid()}')
            with journal.db:
                journal.db.execute('UPDATE observer_delivery_sessions SET document=? WHERE session_id=?',
                                    (encoded(current), current['session_id']))
                journal.db.execute('UPDATE observer_delivery_control SET epoch=? WHERE singleton=1',
                                    ('disarmed-' + secrets.token_hex(24),))
    return current


class DeliverySession:
    """An acceptance file can authorize quality, but cannot re-arm a restarted process."""

    def __init__(self, journal, config, model, channel_config, *, acceptance_path, report_path, now, transport=None):
        self.journal = journal
        self.quality = AcceptedQuality(acceptance_path, report_path, journal=journal,
                                       config=config, model=model, channel=channel_config)
        receipt = self.quality.verify(now)
        self.channel: Channel = Telegram(journal, channel_config, verifier=self.quality,
                                         config_digest=receipt['config_sha256'], transport=transport)
        self.session_id = secrets.token_hex(24)
        self.armed = False
        _sessions(journal)
        document = {'schema_version': 1, 'session_id': self.session_id, 'state': 'waiting',
                    'created_at': utc(now), 'expires_at': utc(now + dt.timedelta(hours=1)),
                    'acceptance_sha256': receipt['sha256'], 'channel': channel_identity(channel_config),
                    'epoch': None, 'actor': None, 'reconciled_at': None}
        with journal.lock() as acquired:
            require(acquired, 'observer_busy')
            with journal.db:
                # Supersede any other instance's send authority without restoring a persisted armed flag.
                journal.db.execute('INSERT INTO observer_delivery_control VALUES(1,?,0) '
                                   'ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch',
                                   ('disarmed-' + self.session_id,))
                journal.db.execute('INSERT INTO observer_delivery_sessions VALUES(?,?,?)',
                                    (self.session_id, utc(now), encoded(document)))

    def status(self, now) -> dict:
        receipt = self.quality.verify(now)
        return {**session_status(self.journal), 'reviewed_precision': self.quality.reviewed_precision(receipt)}

    def tick(self, *, cycle=None, now, poll=True) -> dict:
        try:
            receipt = self.quality.verify(now)
            reviewed = self.quality.reviewed_precision(receipt)
            require(reviewed['precision'] is None or reviewed['precision'] >= .7, 'reviewed_precision_below_floor')
            current = session_status(self.journal)
            require(current.get('session_id') == self.session_id, 'delivery_session_superseded')
            require(current['acceptance_sha256'] == receipt['sha256'], 'acceptance_changed')
            if not self.armed:
                if current['state'] != 'authorized':
                    return {'state': 'disarmed', 'session_id': self.session_id}
                require(now < instant(current['expires_at']), 'reconciliation_expired')
                self.channel.arm_after_reconciliation(current['epoch'], now=now,
                                                       used_today_floor=current.get('used_today_floor'))
                self.armed = True
                current['state'] = 'armed'
                with self.journal.db:
                    self.journal.db.execute('UPDATE observer_delivery_sessions SET document=? WHERE session_id=?',
                                            (encoded(current), self.session_id))
            result = {'state': 'armed'}
            if cycle is not None and cycle['decision'] == 'tell' and cycle['coverage'] == 'complete':
                result['delivery'] = self.channel.deliver(cycle['cycle_id'], now=now)
            if poll:
                result['feedback'] = self.channel.poll_feedback(now=now)
            result['reviewed_precision'] = self.quality.reviewed_precision(receipt)
            if (result['reviewed_precision']['precision'] is not None
                    and result['reviewed_precision']['precision'] < .7):
                self.armed = False
                result.update(state='shadow', error='reviewed_precision_below_floor')
            self._record(result)
            return result
        except ObserverError as exc:
            deferred = ('reconciled_day_budget_unknown', 'model_delivery_budget', 'pre_reconciliation_cycle_refused',
                        'cycle_not_deliverable', 'delivery_cycle_stale', 'restricted_delivery_refused',
                        'phone_review_context_required')
            if self.armed and str(exc) in deferred:
                return {'state': 'armed', 'delivery': {'status': 'deferred', 'error': str(exc)}}
            self.armed = False
            result = {'state': 'shadow', 'error': str(exc)}
            if 'reviewed' in locals():
                result['reviewed_precision'] = reviewed
            self._record(result)
            return result

    def _record(self, result):
        current = session_status(self.journal)
        if current.get('session_id') == self.session_id:
            current.update({k: v for k, v in result.items() if k in ('state', 'error', 'reviewed_precision')})
            with self.journal.db:
                self.journal.db.execute('UPDATE observer_delivery_sessions SET document=? WHERE session_id=?',
                                        (encoded(current), self.session_id))
