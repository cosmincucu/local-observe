"""Owned SQLite journal. Durable attempts, independent feedback and offline replay."""
from __future__ import annotations

import contextlib
import datetime as dt
import itertools
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from .contract import ObserverError, digest, encoded, fields, instant, name, redact, require, strict_json, utc


def private_file(path: Path | str, *, exclusive: bool = False, directory_fd: int | None = None) -> int:
    """Open a regular, owned private file without following a final-component symlink."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(path, flags, 0o600, dir_fd=directory_fd)
    info = os.fstat(fd)
    if not (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
        os.close(fd)
        raise ObserverError('private_owned_file_required')
    return fd


def private_directory(path: Path, *, create: bool = True, reject_git: bool = False) -> int:
    """Walk without following symlinks; anchor subsequent writes to the admitted directory."""
    require(path.is_absolute() and '..' not in path.parts, 'absolute_private_path_required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for index, part in enumerate(path.parts[1:]):
            if reject_git:
                _no_git_marker(fd)
            final = index == len(path.parts) - 2
            if final and create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            if final:
                require(info.st_uid == os.getuid() and mode == 0o700, 'private_owned_directory_required')
            else:
                require(info.st_uid in (0, os.getuid()) and
                        (not mode & 0o022 or info.st_uid == 0 and bool(mode & stat.S_ISVTX)),
                        'unsafe_state_ancestor')
        if reject_git:
            _no_git_marker(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _no_git_marker(directory_fd: int) -> None:
    try:
        os.stat('.git', dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ObserverError('runtime_state_inside_repository')


class Journal:
    """One OS account owns state and human feedback; there is no network feedback listener."""

    def __init__(self, directory: str | Path):
        self.directory = Path(directory).absolute()
        require(self.directory != Path('/'), 'private_owned_directory_required')
        self.directory_fd = private_directory(self.directory, reject_git=True)
        try:
            self._initialize()
        except BaseException:
            if getattr(self, 'db', None) is not None:
                self.db.close()
            os.close(self.directory_fd)
            raise

    def _initialize(self):
        self.anchor = Path(f'/proc/self/fd/{self.directory_fd}')
        require(self.anchor.is_dir(), 'linux_directory_handles_required')
        self.path = self.directory / 'observer.sqlite3'
        os.close(private_file('observer.sqlite3', directory_fd=self.directory_fd))
        for suffix in ('-journal', '-wal', '-shm'):
            sidecar = self.anchor / ('observer.sqlite3' + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                os.close(private_file(sidecar))
        self.db = sqlite3.connect(self.anchor / 'observer.sqlite3', timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA foreign_keys=ON')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        require(version in (0, 1), 'unsupported_journal_version')
        if version == 0:
            require(not self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall(),
                    'unversioned_existing_journal')
        with self.db:
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS cycles (
                    cycle_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, ended_at TEXT,
                    status TEXT NOT NULL, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS feedback (
                    feedback_id TEXT PRIMARY KEY, cycle_id TEXT NOT NULL REFERENCES cycles(cycle_id),
                    recorded_at TEXT NOT NULL, document TEXT NOT NULL);
                PRAGMA user_version=1;
            ''')

    def close(self):
        self.db.close()
        os.close(self.directory_fd)

    def create_file(self, target: str | Path) -> int:
        path = Path(target)
        require(path.parent.absolute() == self.directory and path.name not in ('.', '..'),
                'output_must_be_in_private_directory')
        return private_file(path.name, exclusive=True, directory_fd=self.directory_fd)

    def get(self, cycle_id: str) -> dict | None:
        name(cycle_id)
        row = self.db.execute('SELECT document FROM cycles WHERE cycle_id=?', (cycle_id,)).fetchone()
        return strict_json(row[0], 524288, max_depth=20) if row else None

    def begin(self, cycle_id: str, now: dt.datetime, window: dict, mode: str) -> tuple[dict, bool]:
        name(cycle_id)
        document = {'schema_version': 1, 'cycle_id': cycle_id, 'started_at': utc(now), 'ended_at': None,
                    'status': 'running', 'coverage': 'unknown', 'decision': None, 'error': None,
                    'window': window, 'mode': mode, 'evidence': [], 'activity': [], 'model_calls': [],
                    'answer': None, 'review': 'unknown', 'delivery': {'status': 'not_attempted'},
                    'elapsed_seconds': None}
        with self.db:
            changed = self.db.execute(
                'INSERT OR IGNORE INTO cycles VALUES(?,?,NULL,?,?)',
                (cycle_id, utc(now), 'running', encoded(document))).rowcount
        return (document, True) if changed else (self.get(cycle_id), False)

    def save(self, document: dict) -> None:
        payload = encoded(document)
        require(len(payload.encode()) <= 524288, 'cycle_record_too_large')
        with self.db:
            self.db.execute('UPDATE cycles SET ended_at=?,status=?,document=? WHERE cycle_id=?',
                            (document['ended_at'], document['status'], payload, document['cycle_id']))

    @contextlib.contextmanager
    def lock(self):
        # flock releases on process death. A lease expiry cannot create two active observers.
        import fcntl
        fd = private_file('observer.lock', directory_fd=self.directory_fd)
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
            yield acquired
        finally:
            if acquired:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def recover(self, now: dt.datetime) -> int:
        """Call only under the exclusive observer lock. No attempt is silently replayed."""
        rows = self.db.execute("SELECT document FROM cycles WHERE status='running'").fetchall()
        for row in rows:
            document = strict_json(row[0], 524288, max_depth=20)
            document.update(status='failed', coverage='failed', decision=None, error='interrupted', ended_at=utc(now))
            if document['delivery']['status'] == 'sending':
                document['delivery']['status'] = 'uncertain'
            self.save(document)
        return len(rows)

    def feedback(self, cycle_id: str, feedback_id: str, values: dict, *, now: dt.datetime | None = None) -> dict:
        """Explicit local human review, identified from the OS account, separate from model output."""
        name(feedback_id)
        cycle = self.get(cycle_id)
        require(cycle is not None and cycle['status'] in ('completed', 'partial', 'failed'), 'cycle_not_reviewable')
        fields(values, {'usefulness', 'correctness'},
               {'corrected_answer', 'outcome_refs', 'export_approved', 'review_seconds'})
        require(values['usefulness'] in ('useful', 'noise', 'unsure'), 'invalid_usefulness')
        require(values['correctness'] in ('correct', 'incorrect', 'unsure'), 'invalid_correctness')
        correction = values.get('corrected_answer')
        require(correction is None or isinstance(correction, str) and 1 <= len(correction) <= 4000,
                'invalid_corrected_answer')
        refs = values.get('outcome_refs', [])
        require(isinstance(refs, list) and len(refs) <= 20 and all(isinstance(r, str) for r in refs),
                'invalid_outcome_refs')
        known = {item['evidence_id'] for item in cycle['evidence']}
        require(all(r in known for r in refs), 'unknown_outcome_reference')
        approved = values.get('export_approved', False)
        review_seconds = values.get('review_seconds')
        require(review_seconds is None or type(review_seconds) is int and 0 <= review_seconds <= 3600,
                'invalid_review_seconds')
        require(type(approved) is bool, 'invalid_export_approval')
        require(not approved or bool(correction) and values['correctness'] != 'unsure' and bool(known),
                'corrected_evidence_required_for_export')
        document = {'schema_version': 1, 'feedback_id': feedback_id, 'cycle_id': cycle_id,
                    'reviewer': f'os-uid:{os.getuid()}', 'recorded_at': utc(now or dt.datetime.now(dt.timezone.utc)),
                    'usefulness': values['usefulness'], 'correctness': values['correctness'],
                    'corrected_answer': redact(correction), 'outcome_refs': refs, 'export_approved': approved,
                    'review_seconds': review_seconds}
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO feedback VALUES(?,?,?,?)',
                            (feedback_id, cycle_id, document['recorded_at'], encoded(document)))
            old = strict_json(self.db.execute('SELECT document FROM feedback WHERE feedback_id=?',
                                              (feedback_id,)).fetchone()[0])
            old.setdefault('review_seconds', None)
            require({k: v for k, v in old.items() if k != 'recorded_at'} ==
                    {k: v for k, v in document.items() if k != 'recorded_at'}, 'feedback_id_reused')
        return old

    def replay(self, cycle_id: str) -> dict:
        cycle = self.get(cycle_id)
        require(cycle is not None, 'unknown_cycle')
        feedback = [strict_json(r[0]) for r in self.db.execute(
            'SELECT document FROM feedback WHERE cycle_id=? ORDER BY rowid', (cycle_id,))]
        for review in feedback:
            review.setdefault('review_seconds', None)
        return {**cycle, 'review': 'reviewed' if feedback else 'unknown', 'feedback': feedback}

    def examples(self, *, query: str = '', limit: int = 10) -> list[dict]:
        """Latest independent correction only; scalar grades never create training examples."""
        require(type(limit) is int and 1 <= limit <= 100 and isinstance(query, str) and len(query) <= 200,
                'invalid_retrieval_bound')
        return list(itertools.islice(self._examples(query), limit))

    def _examples(self, query=''):
        rows = self.db.execute('''
            SELECT f.document,c.document FROM feedback f JOIN cycles c USING(cycle_id)
            WHERE f.rowid=(SELECT max(f2.rowid) FROM feedback f2 WHERE f2.cycle_id=f.cycle_id)
            ORDER BY f.rowid DESC LIMIT 1000
        ''')
        for row in rows:
            review, cycle = strict_json(row[0]), strict_json(row[1], 524288, max_depth=20)
            if not review['export_approved'] or not review['corrected_answer']:
                continue
            if query and query.casefold() not in encoded(cycle['evidence']).casefold():
                continue
            yield {'schema_version': 1, 'trust': 'untrusted_reference_only', 'cycle_id': cycle['cycle_id'],
                   'evidence': cycle['evidence'], 'answer': review['corrected_answer'], 'feedback': review}

    def retrieve(self, *, before: dt.datetime, limit: int, max_bytes: int, exclude: str) -> list[dict]:
        """Older independent corrections only, bounded whole examples; no partial/truncated targets."""
        require(type(limit) is int and 0 <= limit <= 10 and type(max_bytes) is int
                and 0 <= max_bytes <= 65536, 'invalid_retrieval_bound')
        result = []
        if not limit:
            return result
        for example in itertools.islice(self._examples(), 100):
            feedback = example['feedback']
            if (example['cycle_id'] == exclude or instant(feedback['recorded_at']) >= before
                    or any(instant(item['window']['end']) >= before for item in example['evidence'])):
                continue
            classes = [item.get('data_class') for item in example['evidence']]
            if not classes or any(c not in ('public', 'internal', 'restricted') for c in classes):
                continue
            content = {'trust': 'untrusted_historical_example', 'cycle_id': example['cycle_id'],
                       'feedback_id': feedback['feedback_id'], 'evidence': example['evidence'],
                       'corrected_answer': feedback['corrected_answer'],
                       'data_class': max(classes, key=('public', 'internal', 'restricted').index)}
            content['history_id'] = digest({'cycle_id': content['cycle_id'], 'feedback_id': content['feedback_id']})
            content['sha256'] = digest(content)
            if len(encoded([*result, content]).encode()) > max_bytes:
                continue
            result.append(content)
            if len(result) == limit:
                break
        return result

    def check(self, *, now: dt.datetime, max_age_seconds: int) -> dict:
        """Freshness of the newest finished cycle; a running cycle never refreshes or hides it."""
        # A running row carries no completion, so the newest finished row keeps deciding health with
        # its own unchanged ended_at. Only a journal without any finished row describes the attempt.
        finished = "SELECT document FROM cycles WHERE status<>'running' ORDER BY rowid DESC LIMIT 1"
        row = (self.db.execute(finished).fetchone()
               or self.db.execute('SELECT document FROM cycles ORDER BY rowid DESC LIMIT 1').fetchone())
        latest = strict_json(row[0], 524288, max_depth=20) if row else None
        healthy = bool(latest and latest['status'] == 'completed' and latest['coverage'] == 'complete'
                       and latest['ended_at'] and 0 <= (now - instant(latest['ended_at'])).total_seconds()
                       <= max_age_seconds)
        return {'schema_version': 1, 'healthy': healthy, 'cycle_id': latest['cycle_id'] if latest else None,
                'status': latest['status'] if latest else 'never_run',
                'coverage': latest['coverage'] if latest else 'unknown',
                'ended_at': latest['ended_at'] if latest else None,
                'meaning': 'execution_and_coverage_only; human_review_is_separate'}

    def backup(self, target: str | Path) -> None:
        path = Path(target)
        require(path.parent.resolve() == self.directory.resolve(), 'backup_must_be_in_private_directory')
        os.close(self.create_file(path))
        with sqlite3.connect(self.anchor / path.name) as destination:
            self.db.backup(destination)
            require(destination.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', 'backup_integrity_failed')
