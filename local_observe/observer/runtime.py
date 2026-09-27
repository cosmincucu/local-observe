"""Single-process cycles under a kernel lock, with a hard wall-clock deadline on Unix."""
from __future__ import annotations

import contextlib
import datetime as dt
import signal
import threading
import time
import uuid
from dataclasses import asdict, replace

from .adapters import Model, Sources
from .contract import Config, ObserverError, digest, encoded, model_answer, redact, require, snapshot, utc
from .journal import Journal


@contextlib.contextmanager
def deadline(seconds: int):
    require(threading.current_thread() is threading.main_thread() and hasattr(signal, 'setitimer'),
            'unix_main_thread_required')
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'existing_alarm_conflict')

    def expired(_signum, _frame):
        # BaseException avoids existing transports swallowing a total-deadline expiry as an OSError.
        raise CycleDeadline()

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class CycleDeadline(BaseException):
    pass


class Observer:
    def __init__(self, config: Config, journal: Journal, *, sources=None, model=None, clock=None):
        self.config, self.journal = config, journal
        self.sources = sources if sources is not None else Sources(config)
        self.model = model if model is not None else Model()
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))

    def run(self, cycle_id: str | None = None) -> dict:
        now, began = self.clock(), time.monotonic()
        cycle_id = cycle_id or 'cycle-' + uuid.uuid4().hex
        window = {'start': utc(now - dt.timedelta(seconds=self.config.window_seconds)), 'end': utc(now)}
        with self.journal.lock() as acquired:
            existing = self.journal.get(cycle_id)
            if existing is not None:
                if acquired and existing['status'] == 'running':
                    self.journal.recover(now)
                return self.journal.get(cycle_id)
            if acquired:
                self.journal.recover(now)
            document, created = self.journal.begin(cycle_id, now, window, self.config.mode)
            if not created:
                return document
            document['config_sha256'] = digest(asdict(self.config))
            self.journal.save(document)
            if not acquired:
                document.update(status='skipped', coverage='skipped', error='already_running')
                return self._finish(document, began)
            try:
                with deadline(self.config.max_cycle_seconds):
                    self._cycle(document, now)
            except CycleDeadline:
                document.update(status='failed', coverage='failed', decision=None, error='cycle_deadline')
            except (KeyboardInterrupt, SystemExit):
                document.update(status='failed', coverage='failed', decision=None, error='interrupted')
                self._finish(document, began)
                raise
            except Exception as exc:
                # Never persist exception prose: transports and parsers can include payloads.
                code = str(exc) if isinstance(exc, ObserverError) else 'cycle_failed'
                document.update(status='failed', coverage='failed', decision=None, error=code)
            return self._finish(document, began)

    def _finish(self, document: dict, began: float) -> dict:
        for call in document['model_calls']:
            if call['status'] == 'running':
                call['status'] = 'failed'
        for activity in document['activity']:
            if activity['status'] == 'running':
                activity['status'] = 'failed'
        document['ended_at'] = utc(self.clock())
        document['elapsed_seconds'] = round(time.monotonic() - began, 6)
        self.journal.save(document)
        return document

    def _cycle(self, document: dict, now: dt.datetime) -> None:
        sources = {s.id: s for s in self.config.sources}
        pending = [s.id for s in self.config.sources if s.initial]
        queried: set[str] = set()
        partial = False
        while True:
            for source_id in pending:
                if len(queried) >= self.config.max_sources:
                    document['activity'].append({'source': source_id, 'status': 'skipped', 'error': 'source_budget'})
                    partial = True
                    continue
                source = sources[source_id]
                queried.add(source_id)
                activity = {'source': source_id, 'query_type': source.query_type, 'status': 'running',
                            'error': None, 'elapsed_seconds': None}
                document['activity'].append(activity)
                self.journal.save(document)
                began = time.monotonic()
                try:
                    raw = self.sources.read(source, document['window'], now)
                    item = snapshot(source, raw, document['window'], self.config, now,
                                    getattr(self.sources, 'secrets', ()))
                    require(len(encoded([*document['evidence'], item]).encode()) <= self.config.max_result_bytes,
                            'cycle_evidence_budget')
                    document['evidence'].append(item)
                    activity.update(status=item['coverage'], evidence_id=item['evidence_id'])
                    partial = partial or item['coverage'] != 'complete'
                except Exception as exc:
                    activity.update(status='failed', error=str(exc) if isinstance(exc, ObserverError)
                                    else 'source_unavailable')
                    partial = True
                activity['elapsed_seconds'] = round(time.monotonic() - began, 6)
                self.journal.save(document)
            evidence = [item for item in document['evidence'] if item['rows']]
            if not evidence:
                document.update(status='failed', coverage='failed', error='no_usable_evidence')
                return
            if len(document['model_calls']) >= self.config.max_model_calls:
                document.update(status='partial', coverage='partial', decision=None, error='model_budget')
                return
            allowed = set(sources) - queried
            call = {'number': len(document['model_calls']) + 1, 'status': 'running', 'model': None,
                    'response_model': None, 'usage': {'input_tokens': None, 'output_tokens': None},
                    'elapsed_seconds': None, 'cost': None}
            document['model_calls'].append(call)
            self.journal.save(document)
            began = time.monotonic()
            classes = ('public', 'internal', 'restricted')
            classification = max((item['data_class'] for item in evidence), key=classes.index)
            result = self.model.complete(evidence, allowed, replace(self.config, data_class=classification), now)
            require(isinstance(result, dict) and isinstance(result.get('content'), str), 'invalid_model_envelope')
            for key in ('model', 'response_model'):
                value = result.get(key)
                require(value is None or isinstance(value, str) and len(value) <= 160, 'invalid_model_metadata')
                call[key] = redact(value, getattr(self.model, 'secrets', ()))
            usage = result.get('usage', {})
            require(isinstance(usage, dict), 'invalid_model_usage')
            for key in ('input_tokens', 'output_tokens'):
                value = usage.get(key)
                require(value is None or type(value) is int and 0 <= value <= 10000000, 'invalid_model_usage')
                call['usage'][key] = value
            call['elapsed_seconds'] = round(time.monotonic() - began, 6)
            answer = model_answer(result['content'], evidence, allowed)
            answer = redact(answer, (*getattr(self.sources, 'secrets', ()), *getattr(self.model, 'secrets', ())))
            call.update(status='completed', answer=answer)
            self.journal.save(document)
            pending = answer['follow_up']
            if pending:
                if (len(document['model_calls']) >= self.config.max_model_calls
                        or len(queried) >= self.config.max_sources):
                    document.update(status='partial', coverage='partial', decision=None, error='follow_up_budget')
                    return
                continue
            document.update(status='partial' if partial else 'completed', coverage='partial' if partial else 'complete',
                            answer=answer, decision='watch' if partial and answer['decision'] == 'quiet'
                            else answer['decision'])
            # This outbox is deliberately recording-only until independent evaluation authorizes a provider.
            # A stable cycle key and immutable duplicate return prevent repeated recording after restart.
            document['delivery'] = {'status': 'recorded', 'id': 'record-' + document['cycle_id'],
                                    'channel': 'recording', 'external_send': False, 'evaluation': 'not_approved'}
            return

    def serve(self, *, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        while not stop.is_set():
            now = self.clock()
            slot = int(now.timestamp()) // self.config.cadence_seconds
            self.run(f'scheduled-{self.config.cadence_seconds}-{slot}')
            remaining = (slot + 1) * self.config.cadence_seconds - self.clock().timestamp()
            stop.wait(max(0.1, min(remaining, self.config.cadence_seconds)))
