"""Optional, explicitly armed delivery and authenticated pull feedback.

The parent supplies independent evaluation verification. There is no default verifier,
automatic arming, rule-notification budget, webhook or model-visible credential.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import urllib.error
import urllib.request
import urllib.parse
import uuid
from dataclasses import asdict, dataclass
from collections.abc import Callable

from local_observe.http import NoRedirect

from .adapters import credential
from .contract import ObserverError, digest, encoded, fields, instant, require, strict_json, utc
from .journal import Journal
from .runtime import deadline


@dataclass(frozen=True)
class TelegramConfig:
    token_file: str
    chat_id: int
    user_id: int
    daily_limit: int = 2
    feedback_seconds: int = 86400
    review_base_url: str | None = None

    def __post_init__(self):
        from pathlib import Path
        require(isinstance(self.token_file, str) and Path(self.token_file).is_absolute(),
                'telegram_credential_file_required')
        require(type(self.chat_id) is int and 0 < abs(self.chat_id) < 2**63
                and type(self.user_id) is int and 0 < self.user_id < 2**63,
                'telegram_identity_required')
        require(type(self.daily_limit) is int and 1 <= self.daily_limit <= 2, 'telegram_daily_limit')
        require(type(self.feedback_seconds) is int and 60 <= self.feedback_seconds <= 86400,
                'telegram_feedback_expiry')
        if self.review_base_url is not None:
            parsed = urllib.parse.urlsplit(self.review_base_url)
            require(parsed.scheme == 'https' and bool(parsed.hostname) and not parsed.username
                    and not parsed.password and not parsed.query and not parsed.fragment
                    and len(self.review_base_url) <= 300, 'invalid_review_url')


class TelegramTransport:
    """Fixed TLS host, no inherited proxy or redirects, no logging of token-bearing paths."""

    def __init__(self, token_file: str):
        import re
        self.token = credential(token_file)
        require(re.fullmatch(r'[0-9]{1,20}:[A-Za-z0-9_-]{20,120}', self.token) is not None,
                'invalid_telegram_credential')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method: str, payload: dict) -> dict:
        require(method in ('sendMessage', 'getUpdates'), 'unsupported_telegram_method')
        request = urllib.request.Request('https://api.telegram.org/bot' + self.token + '/' + method,
                                         data=encoded(payload).encode(), method='POST',
                                         headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=10) as response:
                body = strict_json(response.read(1048577), 1048576)
            require(isinstance(body, dict) and body.get('ok') is True, 'telegram_response_refused')
            return body['result']
        except Exception as exc:
            # Even a provider error is conservatively uncertain after dispatch; no retry branch exists.
            raise ObserverError('telegram_transport_uncertain') from exc


class Telegram:
    """A replaceable post-cycle sink. All sends require a separate, trusted evaluation verifier.

    verifier(cycle, binding, now) must independently authorize the exact supplied binding;
    it must never trust an approval field from telemetry/model output. Parent integration
    owns signed-quality artifact validation. No callback can authorize an action or send.
    """

    def __init__(self, journal: Journal, config: TelegramConfig, *, verifier: Callable,
                 config_digest: str, transport=None):
        require(callable(verifier), 'independent_evaluation_verifier_required')
        require(isinstance(config_digest, str) and len(config_digest) == 64
                and all(c in '0123456789abcdef' for c in config_digest), 'invalid_configuration_digest')
        self.journal, self.config, self.verifier = journal, config, verifier
        self.config_digest, self.transport = config_digest, transport
        self.epoch: str | None = None
        with journal.db:
            journal.db.executescript('''
                CREATE TABLE IF NOT EXISTS observer_delivery_control (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch TEXT NOT NULL, cursor INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS observer_deliveries (
                    cycle_id TEXT PRIMARY KEY REFERENCES cycles(cycle_id), epoch TEXT NOT NULL,
                    day TEXT NOT NULL, status TEXT NOT NULL, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observer_reconciliations (
                    epoch TEXT PRIMARY KEY, document TEXT NOT NULL);
            ''')

    def arm_after_reconciliation(self, epoch: str, *, now: dt.datetime | None = None,
                                 used_today_floor: int | None = None) -> None:
        """Explicit operator boundary, needed for every process/restore; use a fresh UUID epoch.

        Reconcile previous external effects before calling. There is deliberately no
        environment flag or persisted armed bit that could re-arm an old backup.
        """
        try:
            require(str(uuid.UUID(epoch)) == epoch, 'fresh_delivery_epoch_required')
        except (ValueError, TypeError, AttributeError) as exc:
            raise ObserverError('fresh_delivery_epoch_required') from exc
        with self.journal.lock() as acquired:
            require(acquired, 'observer_busy')
            now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
            day = now.date().isoformat()
            spent = self.journal.db.execute('SELECT count(*) FROM observer_deliveries WHERE day=?',
                                            (day,)).fetchone()[0]
            # A later epoch cannot erase a human-confirmed spend floor from an earlier restore.
            for row in self.journal.db.execute('SELECT document FROM observer_reconciliations WHERE document LIKE ?',
                                                ('%"day":"' + day + '"%',)):
                previous = strict_json(row[0])
                if previous['not_before'] != previous['reconciled_at']:
                    continue  # Unknown spend deferred that epoch; it was not a human count.
                later = self.journal.db.execute('SELECT count(*) FROM observer_deliveries WHERE day=? AND rowid>?',
                                                (day, previous['delivery_row_floor'])).fetchone()[0]
                spent = max(spent, previous['used_today_floor'] + later)
            require(used_today_floor is None or type(used_today_floor) is int
                    and spent <= used_today_floor <= self.config.daily_limit, 'reconciled_spend_below_known_count')
            next_day = dt.datetime.combine(now.date() + dt.timedelta(days=1), dt.time(), tzinfo=dt.timezone.utc)
            reconciliation = {'epoch': epoch, 'reconciled_at': utc(now), 'day': day,
                              'not_before': utc(next_day if used_today_floor is None else now),
                              'used_today_floor': (self.config.daily_limit if used_today_floor is None
                                                   else used_today_floor),
                              'cycle_row_floor': self.journal.db.execute(
                                  'SELECT coalesce(max(rowid),0) FROM cycles').fetchone()[0],
                              'delivery_row_floor': self.journal.db.execute(
                                  'SELECT coalesce(max(rowid),0) FROM observer_deliveries').fetchone()[0]}
            old = self.journal.db.execute('SELECT epoch FROM observer_delivery_control WHERE singleton=1').fetchone()
            require(old is None or old[0] != epoch, 'fresh_delivery_epoch_required')
            require(self.journal.db.execute('SELECT 1 FROM observer_reconciliations WHERE epoch=?',
                                            (epoch,)).fetchone() is None, 'fresh_delivery_epoch_required')
            with self.journal.db:
                self.journal.db.execute('INSERT INTO observer_delivery_control VALUES(1,?,0) '
                                        'ON CONFLICT(singleton) DO UPDATE SET epoch=excluded.epoch,cursor=0', (epoch,))
                self.journal.db.execute('INSERT INTO observer_reconciliations VALUES(?,?)',
                                        (epoch, encoded(reconciliation)))
                rows = self.journal.db.execute(
                    "SELECT document FROM observer_deliveries WHERE status='sending'").fetchall()
                for row in rows:
                    item = strict_json(row[0])
                    item['status'] = 'uncertain'
                    self._save(item)
            self.epoch = epoch

    def _armed(self):
        row = self.journal.db.execute('SELECT epoch FROM observer_delivery_control WHERE singleton=1').fetchone()
        require(self.epoch is not None and row is not None and self.epoch == row[0], 'delivery_not_armed')

    def _save(self, item: dict):
        self.journal.db.execute('UPDATE observer_deliveries SET status=?,document=? WHERE cycle_id=?',
                                (item['status'], encoded(item), item['cycle_id']))

    def outcome(self, cycle_id: str) -> dict | None:
        row = self.journal.db.execute('SELECT document FROM observer_deliveries WHERE cycle_id=?',
                                     (cycle_id,)).fetchone()
        return strict_json(row[0]) if row else None

    def _request(self, method: str, payload: dict):
        if self.transport is None:
            self.transport = TelegramTransport(self.config.token_file)
        return self.transport.request(method, payload)

    def deliver(self, cycle_id: str, *, now: dt.datetime) -> dict:
        with self.journal.lock() as acquired:
            require(acquired, 'observer_busy')
            self._armed()
            previous = self.outcome(cycle_id)
            if previous is not None:
                return previous
            cycle = self.journal.get(cycle_id)
            require(cycle is not None and cycle['status'] == 'completed' and cycle['coverage'] == 'complete'
                    and cycle['decision'] == 'tell' and bool(cycle['answer'].get('findings')), 'cycle_not_deliverable')
            reconciliation = strict_json(self.journal.db.execute(
                'SELECT document FROM observer_reconciliations WHERE epoch=?', (self.epoch,)).fetchone()[0])
            row_id = self.journal.db.execute('SELECT rowid FROM cycles WHERE cycle_id=?', (cycle_id,)).fetchone()[0]
            require(row_id > reconciliation['cycle_row_floor']
                    and instant(cycle['started_at']) >= instant(reconciliation['reconciled_at']),
                    'pre_reconciliation_cycle_refused')
            require(now >= instant(reconciliation['not_before']), 'reconciled_day_budget_unknown')
            require(0 <= (now - instant(cycle['ended_at'])).total_seconds() <= 7200, 'delivery_cycle_stale')
            require(all(item.get('data_class') in ('public', 'internal')
                        for item in [*cycle['evidence'], *cycle.get('retrieval', [])]),
                    'restricted_delivery_refused')
            require(cycle.get('config_sha256') == self.config_digest, 'delivery_configuration_changed')
            model = cycle['model_calls'][-1]['response_model']
            require(isinstance(model, str) and bool(model), 'delivery_model_unknown')
            binding = {'schema_version': 1, 'config_sha256': self.config_digest, 'model': model,
                       'cycle_sha256': digest(cycle), 'channel': 'telegram', 'chat_id': self.config.chat_id,
                       'user_id': self.config.user_id, 'epoch': self.epoch,
                       'review_base_url': self.config.review_base_url, 'daily_limit': self.config.daily_limit,
                       'channel_sha256': digest(asdict(self.config)),
                       'provenance_sha256': (cycle.get('provenance') or {}).get('sha256')}
            require(self.verifier(cycle, binding, now) is True, 'independent_evaluation_required')
            text = self._message(cycle)
            day = now.date().isoformat()
            count = self.journal.db.execute('SELECT count(*) FROM observer_deliveries WHERE day=?',
                                            (day,)).fetchone()[0]
            if day == reconciliation['day']:
                after = self.journal.db.execute('SELECT count(*) FROM observer_deliveries WHERE day=? AND rowid>?',
                                                (day, reconciliation['delivery_row_floor'])).fetchone()[0]
                count = max(count, reconciliation['used_today_floor'] + after)
            require(count < self.config.daily_limit, 'model_delivery_budget')
            nonce = secrets.token_urlsafe(18)
            item = {'schema_version': 1, 'cycle_id': cycle_id, 'epoch': self.epoch, 'day': day,
                    'status': 'sending', 'message_id': None,
                    'chat_id': self.config.chat_id, 'user_id': self.config.user_id,
                    'callback_hash': hashlib.sha256(nonce.encode()).hexdigest(), 'callback_used': False,
                    'callback_expires_at': utc(now + dt.timedelta(seconds=self.config.feedback_seconds)),
                    'binding': binding, 'attempted_at': utc(now)}
            with self.journal.db:
                self.journal.db.execute('INSERT INTO observer_deliveries VALUES(?,?,?,?,?)',
                                        (cycle_id, self.epoch, day, 'sending', encoded(item)))
            # Intent and budget debit are committed before *any* provider I/O, including construction.
            keyboard = []
            for u_code, useful in enumerate(('useful', 'noise', 'unsure')):
                keyboard.append([{'text': f'{useful} / {correct}', 'callback_data': f'lo:{nonce}:{u_code}{c_code}'}
                                 for c_code, correct in enumerate(('correct', 'incorrect', 'unsure'))])
            payload = {'chat_id': self.config.chat_id, 'text': text,
                       'reply_markup': {'inline_keyboard': keyboard}, 'protect_content': True,
                       'link_preview_options': {'is_disabled': True}}
            try:
                with deadline(20):
                    result = self._request('sendMessage', payload)
                require(isinstance(result, dict) and type(result.get('message_id')) is int
                        and isinstance(result.get('chat'), dict) and result['chat'].get('id') == self.config.chat_id,
                        'telegram_receipt_invalid')
                item.update(status='sent', message_id=result['message_id'])
            except BaseException as exc:
                item['status'] = 'uncertain'
                with self.journal.db:
                    self._save(item)
                if not isinstance(exc, Exception):
                    raise
                return item
            with self.journal.db:
                self._save(item)
            return item

    def _message(self, cycle: dict) -> str:
        """Only validated numeric citations/configuration, never arbitrary evidence or model prose."""
        indexed = {e['evidence_id']: e for e in cycle['evidence']}
        lines = ['Observer tell; coverage: complete.']
        for finding in cycle['answer']['findings'][:4]:
            context = []
            for citation in cycle['answer']['citations']:
                if citation['evidence_id'] not in finding['evidence_ids'] or citation['field'] != 'value':
                    continue
                item = indexed[citation['evidence_id']]
                row = item['rows'][citation['row_index']]
                if item['query_type'] == 'metric-threshold' and type(row['value']) in (int, float):
                    context.append(f'{item["metric_name"]}={row["value"]} @ {row["timestamp"]}')
            require(bool(context) or self.config.review_base_url is not None, 'phone_review_context_required')
            lines.append(f'{finding["kind"]} | {finding["resource_id"]} | ' +
                         ('; '.join(context[:2]) if context else finding['observed_at']))
        lines.append('Cycle: ' + cycle['cycle_id'])
        if self.config.review_base_url:
            lines.append(self.config.review_base_url.rstrip('/') + '/' + urllib.parse.quote(cycle['cycle_id'], safe=''))
        lines.append('Grade usefulness / correctness; choose unsure if context is insufficient.')
        text = '\n'.join(lines)
        require(len(text) <= 3500, 'phone_review_context_too_large')
        return text

    def poll_feedback(self, *, now: dt.datetime) -> dict:
        """Authenticate only updates pulled from the fixed Telegram host; commit cursor with review."""
        with self.journal.lock() as acquired:
            require(acquired, 'observer_busy')
            self._armed()
            cursor = self.journal.db.execute(
                'SELECT cursor FROM observer_delivery_control WHERE singleton=1').fetchone()[0]
            with deadline(20):
                updates = self._request('getUpdates', {'offset': cursor, 'limit': 100, 'timeout': 0,
                                                     'allowed_updates': ['callback_query']})
            require(isinstance(updates, list) and len(updates) <= 100, 'invalid_telegram_updates')
            accepted = rejected = 0
            for update in updates:
                require(isinstance(update, dict) and type(update.get('update_id')) is int, 'invalid_telegram_update')
                if update['update_id'] < cursor:
                    continue
                new_cursor = update['update_id'] + 1
                # Every update, including a rejected forgery, advances only within the same DB transaction.
                with self.journal.db:
                    if self._callback(update.get('callback_query'), now):
                        accepted += 1
                    else:
                        rejected += 1
                    self.journal.db.execute('UPDATE observer_delivery_control SET cursor=? WHERE singleton=1',
                                            (new_cursor,))
                cursor = new_cursor
            return {'accepted': accepted, 'rejected': rejected, 'cursor': cursor}

    def _callback(self, callback, now: dt.datetime) -> bool:
        if not isinstance(callback, dict) or not isinstance(callback.get('data'), str):
            return False
        parts = callback['data'].split(':')
        if len(parts) != 3 or parts[0] != 'lo' or len(parts[1]) != 24 or parts[2] not in (
                '00', '01', '02', '10', '11', '12', '20', '21', '22'):
            return False
        nonce_hash = hashlib.sha256(parts[1].encode()).hexdigest()
        rows = self.journal.db.execute(
            "SELECT document FROM observer_deliveries WHERE epoch=? AND status='sent' AND day>=? LIMIT 4",
            (self.epoch, (now - dt.timedelta(days=1)).date().isoformat())).fetchall()
        for row in rows:
            item = strict_json(row[0])
            if not secrets.compare_digest(item['callback_hash'], nonce_hash):
                continue
            message, actor = callback.get('message'), callback.get('from')
            if (item['callback_used'] or not instant(item['attempted_at']) <= now < instant(item['callback_expires_at'])
                    or not isinstance(actor, dict) or type(actor.get('id')) is not int
                    or actor['id'] != item['user_id'] or actor.get('is_bot') is not False
                    or not isinstance(message, dict) or type(message.get('message_id')) is not int
                    or message['message_id'] != item['message_id'] or not isinstance(message.get('chat'), dict)
                    or type(message['chat'].get('id')) is not int or message['chat']['id'] != item['chat_id']):
                return False
            document = {'schema_version': 1, 'feedback_id': 'telegram-' + nonce_hash[:32],
                        'cycle_id': item['cycle_id'], 'reviewer': f'telegram-user:{item["user_id"]}',
                        'recorded_at': utc(now), 'usefulness': ('useful', 'noise', 'unsure')[int(parts[2][0])],
                        'correctness': ('correct', 'incorrect', 'unsure')[int(parts[2][1])],
                        'corrected_answer': None, 'outcome_refs': [], 'export_approved': False, 'review_seconds': None}
            self.journal.db.execute('INSERT INTO feedback VALUES(?,?,?,?)',
                                    (document['feedback_id'], item['cycle_id'], utc(now), encoded(document)))
            item['callback_used'] = True
            self._save(item)
            return True
        return False
