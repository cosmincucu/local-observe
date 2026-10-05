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
from .provenance import build_provenance, validate_route_receipt


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
    def __init__(self, config: Config, journal: Journal, *, sources=None, model=None, clock=None, environ=None):
        self.config, self.journal = config, journal
        self.sources = sources if sources is not None else Sources(config, environ=environ)
        self.model = model if model is not None else Model(environ=environ)
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
            document['retrieval'] = []
            self.journal.save(document)
            if not acquired:
                document.update(status='skipped', coverage='skipped', error='already_running')
                return self._finish(document, began)
            try:
                with deadline(self.config.max_cycle_seconds):
                    document['provenance'] = build_provenance(self.config, self.model)
                    self.journal.save(document)
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
        if 'provenance' not in document:
            document['provenance'] = build_provenance(self.config, None)
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
        history = None
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
                    require(len(encoded([*document['evidence'], item]).encode())
                            + len(encoded(history or []).encode()) - 2 <= self.config.max_result_bytes,
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
            if history is None:
                remaining = self.config.max_result_bytes - len(encoded(document['evidence']).encode())
                history = self.journal.retrieve(before=now, limit=self.config.retrieval_examples,
                                               max_bytes=min(self.config.retrieval_bytes, max(0, remaining)),
                                               exclude=document['cycle_id'])
                document['retrieval'] = [{k: item[k] for k in ('history_id', 'cycle_id', 'feedback_id', 'sha256',
                                                              'data_class')} for item in history]
            allowed = set(sources) - queried
            call = {'number': len(document['model_calls']) + 1, 'status': 'running', 'model': None,
                    'response_model': None, 'usage': {'input_tokens': None, 'output_tokens': None},
                    'elapsed_seconds': None, 'cost': None, 'provenance': document['provenance']}
            document['model_calls'].append(call)
            self.journal.save(document)
            began = time.monotonic()
            classes = ('public', 'internal', 'restricted')
            classification = max((item['data_class'] for item in [*evidence, *history]), key=classes.index)
            call['data_class'] = classification
            request_config = replace(self.config, data_class=classification)
            if history:
                require(callable(getattr(self.model, 'complete_with_history', None)), 'historical_examples_unsupported')
                result = self.model.complete_with_history(evidence, allowed, request_config, now, history=history)
            else:
                result = self.model.complete(evidence, allowed, request_config, now)
            require(isinstance(result, dict) and isinstance(result.get('content'), str), 'invalid_model_envelope')
            call['provenance'] = build_provenance(self.config, self.model, response_model=result.get('response_model'))
            document['provenance'] = call['provenance']
            if 'model_route' in result:
                call['model_route'] = validate_route_receipt(result['model_route'], call['provenance'])
                require(all(c.get('model_route', {}).get('pool_sha256') == call['model_route']['pool_sha256']
                            for c in document['model_calls'][:-1]), 'mixed_model_provenance')
            require(call['provenance']['provider'] != 'declared-route-pool' or 'model_route' in call,
                    'model_route_receipt_required')
            previous = [c.get('provenance') for c in document['model_calls'][:-1]]
            require(not previous or all(p == call['provenance'] for p in previous), 'mixed_model_provenance')
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

    def serve(self, *, stop: threading.Event | None = None, delivery=None, on_delivery=None) -> None:
        stop = stop or threading.Event()
        last_slot = None
        while not stop.is_set():
            now = self.clock()
            if delivery is not None:
                delivery.tick(now=now, poll=False)
            slot = int(now.timestamp()) // self.config.cadence_seconds
            cycle = None
            if slot != last_slot:
                cycle = self.run(f'scheduled-{self.config.cadence_seconds}-{slot}')
                last_slot = slot
            if delivery is not None:
                result = delivery.tick(cycle=cycle, now=self.clock())
                if on_delivery is not None:
                    on_delivery(result)
            remaining = (slot + 1) * self.config.cadence_seconds - self.clock().timestamp()
            stop.wait(max(0.1, min(remaining, 30 if delivery else self.config.cadence_seconds)))
