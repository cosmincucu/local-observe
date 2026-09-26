"""The anomaly producer's durable cursor: what is owed, in whose words, and what refuses to say it.

The cursor is one JSON file that decides what the producer remembers after a restart, so almost every
test here is about a *refusal* or an *arithmetic*, never about the verdict maths (that stays in
``tests/test_anomaly.py``). Three properties carry the card:

* **the pending batch is the request.** The stored payloads must re-serialise, byte for byte, to what
  ``http.JsonClient`` puts on the wire — checked against the real client with its transport mocked, so
  a change on either side that breaks that equality fails here instead of shipping a producer that
  replays a *different* request than the one it promised;
* **a refusal is read-only.** Every rejection asserts the bytes on disk afterwards, because a monitor
  that repairs its own memory by rewriting it is how an outage becomes a clean sheet; and
* **the resume point is the cursor, not the clock.** The hour the producer was down is exactly when
  this matters, so the arithmetic is tested with the clock moved far ahead.

The cursor's own unit contract, its backup and its restore path: ``docs/units/anomaly-cursor.md``.
"""
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.http import JsonClient
from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.platform import anomaly, anomaly_cursor
from local_observe.platform.anomaly_cursor import CursorRefusal
from local_observe.platform.detections import event

RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
OTHER_RESOURCE = '00000000-0000-4000-8000-000000000000'
SOURCE = 'anomaly-test'
SQL = ('SELECT toUnixTimestamp(t) AS ts, avg(v) AS v FROM signoz_traces.distributed_timeseries '
       'WHERE t >= {start_s:UInt64} AND t < {end_s:UInt64} GROUP BY ts ORDER BY ts FORMAT JSON')
END_S = int(timestamp('2026-08-05T00:00:00Z').timestamp())
EVALUATION = 3600


def private(directory: Path) -> Path:
    """Create a directory a cursor is allowed to live in: mode 0700 on a POSIX host.

    The producer refuses a parent that group or other can reach, so a fixture has to make the one it
    would accept. The mode bits state nothing on Windows and the refusal is gated to POSIX in
    :func:`~local_observe.platform.anomaly_cursor.private_parent`, so nothing is chmodded there.
    """
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':
        os.chmod(directory, 0o700)
    return directory


def make_link(link: Path, target: Path, *, directory: bool = False) -> None:
    """Create *link* pointing at *target*, or skip only where Windows withholds the privilege.

    The gate is the one genuine platform feature check there is: creating a symbolic link on Windows
    needs ``SeCreateSymbolicLinkPrivilege``, which a normal account does not hold, and the OS says so
    with ``winerror == 1314``. **Anything else is a failure, not a skip** — an unexpected
    :class:`OSError` (a path that cannot be written, a filesystem that cannot hold a link) or a
    :class:`NotImplementedError` is a defect in this suite or in the host, and turning one of those
    into a green skip is how a refusal test stops testing anything. Linux CI runs every link case for
    real; see the narrow OS-gate table in ``docs/testing-standards.md``.
    """
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if os.name == 'nt' and getattr(exc, 'winerror', None) == 1314:
            raise SkipSymlink from exc
        raise
    except NotImplementedError:
        raise


class SkipSymlink(Exception):
    """Raised by :func:`make_link` and turned into a skip by the test that asked for the link.

    Only :func:`make_link` raises it, and only on the one Windows privilege gate it names.
    """


def text(end_s: int) -> str:
    """Return the canonical UTC text the producer writes for *end_s*."""
    return utc_text(dt.datetime.fromtimestamp(end_s, dt.timezone.utc))


def batch(*, source: str = SOURCE, end_s: int = END_S, status: str = 'firing',
          sample_id: str = 'sample-1', value: float = 30.0) -> tuple[dict, dict, dict]:
    """Return one window with the sample and the event the producer would POST for it.

    The event comes from the real `detections.event` factory and not a hand-built dict, so the cursor
    is validated against the shape the platform itself accepts.
    """
    window = {'start': text(end_s - EVALUATION), 'end': text(end_s)}
    finding = event(source, RESOURCE, 'anomaly.demo-load', 'anomaly', status, window,
                    {'rule_id': 'anomaly.demo-load', 'sample_id': sample_id},
                    query_type='metric-threshold')
    sample = {'sample_id': sample_id, 'observed_at': window['end'], 'ok': True, 'value': value}
    return window, sample, finding


class Answer(io.BytesIO):
    """A transport answer shaped the way `JsonClient` reads one: a body and a status."""

    def __init__(self, body: bytes = b'{"status":"accepted"}', status: int = 200) -> None:
        super().__init__(body)
        self.status = status


class CursorFixture(unittest.TestCase):
    """Scratch: a private parent, real resolved series, and byte-level reads of the cursor file."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = private(self.root / 'cursor')

    def entry(self, **overrides) -> dict:
        entry = {'id': 'demo-load', 'resource_id': RESOURCE, 'sql': SQL, 'evaluation_seconds': EVALUATION,
                 'sql_sha256': hashlib.sha256(SQL.encode()).hexdigest()}
        entry.update(overrides)
        if 'sql' in overrides and 'sql_sha256' not in overrides:
            entry['sql_sha256'] = hashlib.sha256(overrides['sql'].encode()).hexdigest()
        return entry

    def all_series(self, *entries: dict, **document: object) -> list[dict]:
        """Return every series of a configuration written through the producer's own loader."""
        path = self.root / 'anomaly.json'
        path.write_text(json.dumps({'series': list(entries) or [self.entry()], **document}),
                        encoding='utf-8')
        return anomaly.load_config(path)['series']

    def resolved(self, *entries: dict, **document: object) -> dict:
        return self.all_series(*entries, **document)[0]

    def series(self, **overrides) -> dict:
        return self.resolved(self.entry(**overrides))

    def path(self, name: str = 'anomaly-cursor.json') -> Path:
        return self.directory / name

    def bytes_of(self, path: Path | None = None) -> bytes:
        return (path or self.path()).read_bytes()

    def fresh(self) -> dict:
        return anomaly_cursor.empty_document(SOURCE)

    def held(self, **series_overrides) -> dict:
        """Return a valid document with one entry for the default series, nothing judged yet."""
        document = self.fresh()
        anomaly_cursor.ensure_entry(document, self.series(**series_overrides))
        return document

    def saved(self, document: dict | None = None, name: str = 'anomaly-cursor.json') -> Path:
        path = self.path(name)
        anomaly_cursor.save(path, document if document is not None else self.held())
        return path

    def with_pending(self, **overrides) -> tuple[dict, dict, dict, dict]:
        """Return a document holding one owed batch, with the window, sample and event behind it."""
        document = self.held()
        window, sample, finding = batch(**overrides)
        anomaly_cursor.begin(document, self.series(), window=window, sample=sample, event=finding)
        return document, window, sample, finding


class TraversalTests(CursorFixture):
    """Links above the cursor: the whole ancestry is the boundary, tested without a link privilege.

    These run on Windows as well as Linux because they substitute for the one filesystem question the
    check asks (`symlink_present`), which is what lets the *shape* of the traversal be pinned on every
    platform. Creating a real link stays an integration test (`make_link`), gated only on the Windows
    privilege that withholds it.
    """

    def pretend_linked(self, *candidates: Path):
        """Return a patch making exactly *candidates* read as symbolic links, and nothing else."""
        targets = set(candidates)
        return mock.patch.object(anomaly_cursor, 'symlink_present', lambda candidate: candidate in targets)

    def test_a_link_above_the_parent_directory_is_refused_before_the_file_is_opened(self):
        path = self.saved()
        before = self.bytes_of(path)
        with self.pretend_linked(self.directory):
            with self.assertRaises(CursorRefusal) as refused:
                anomaly_cursor.load(path, source=SOURCE)
        self.assertIn('symlinked directory', str(refused.exception))
        self.assertEqual(self.bytes_of(path), before, 'a refused read read nothing and wrote nothing')

    def test_a_link_above_the_parent_directory_refuses_the_write_without_creating_a_temp(self):
        path = self.saved()
        with self.pretend_linked(self.directory):
            with self.assertRaises(CursorRefusal):
                anomaly_cursor.save(path, self.held())
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()),
                         ['anomaly-cursor.json'], 'no temporary file is made inside a linked tree')

    def test_the_immediate_parent_is_still_named_as_a_link_by_itself(self):
        path = self.saved()
        with self.pretend_linked(self.directory):
            with self.assertRaises(CursorRefusal) as refused:
                anomaly_cursor.private_parent(path)
        self.assertIn('symlink', str(refused.exception))

    def test_a_link_somewhere_else_in_the_directory_is_not_read_as_the_cursor_s(self):
        """The walk covers the ancestry and nothing else, or every cursor in a directory is suspect."""
        path = self.saved()
        sibling = self.directory / 'another-service.json'
        sibling.write_text('{}', encoding='utf-8')
        with self.pretend_linked(sibling):
            self.assertEqual(anomaly_cursor.load(path, source=SOURCE), self.held())
            anomaly_cursor.private_parent(path)


class TurnTests(CursorFixture):
    """The round-robin position: one name in the file, bounded, and not a count that can saturate."""

    def test_the_turn_is_recorded_for_the_series_that_took_it(self):
        document = self.fresh()
        series = self.series()
        self.assertIsNone(document['last_served'], 'nobody has been served yet, so the head goes first')
        self.assertEqual(anomaly_cursor.serve(document, series), 'demo-load')
        self.assertEqual(document['last_served'], 'demo-load')
        self.assertIn('demo-load', document['series'], 'taking a turn also means being in the file')

    def test_the_rotation_wraps_past_the_served_series_and_is_bounded(self):
        document = self.fresh()
        names = ['a', 'b', 'c']
        self.assertEqual(anomaly_cursor.rotation(document, names), names)
        successors: set = set()
        for name in names:
            document['last_served'] = name
            rotated = anomaly_cursor.rotation(document, names)
            self.assertEqual(rotated, names[names.index(name) + 1:] + names[:names.index(name) + 1],
                             'the list starts after the served series and wraps')
            self.assertEqual(len(rotated), len(names), 'a rotation drops nothing')
            successors.add(rotated[0])
        self.assertEqual(successors, {'a', 'b', 'c'},
                         "every series is somebody's successor, so none can be skipped forever")

    def test_the_turn_survives_the_file_a_restart_reads(self):
        document = self.held()
        anomaly_cursor.serve(document, self.series())
        path = self.saved(document)
        self.assertEqual(anomaly_cursor.load(path, source=SOURCE)['last_served'], 'demo-load')

    def test_a_marker_naming_a_series_that_left_the_configuration_restarts_the_rotation(self):
        document = self.fresh()
        document['last_served'] = 'a-series-nobody-configures'
        self.assertEqual(anomaly_cursor.rotation(document, ['kept', 'other']), ['kept', 'other'])
        anomaly_cursor.save(self.path(), document)   # tolerated: the marker is a position, not an id
        self.assertEqual(anomaly_cursor.load(self.path(), source=SOURCE)['last_served'],
                         'a-series-nobody-configures')

    def test_counters_at_the_ceiling_still_write_and_still_take_turns(self):
        """`MAX_COUNT` must be a clamp and not a wall the producer walks into.

        The ceiling is also what `load` refuses past, so a counter that grew past it would make every
        later save fail: a cursor holding an undelivered batch that can no longer record anything.
        Clamping keeps the document writable, and because the scheduler reads a name rather than a
        number, a saturated series keeps its place in the rotation.
        """
        document = self.held()
        state = document['series']['demo-load']
        anomaly_cursor.serve(document, self.series())
        for field in ('delivered', 'no_verdict', 'refusals'):
            state[field] = anomaly_cursor.MAX_COUNT
            anomaly_cursor.note_refusal(document, self.series())
            self.assertEqual(state[field], anomaly_cursor.MAX_COUNT, 'the count saturates here')
        path = self.saved(document)
        reopened = anomaly_cursor.load(path, source=SOURCE)
        self.assertEqual(reopened['series']['demo-load']['refusals'], anomaly_cursor.MAX_COUNT)
        self.assertEqual(reopened['last_served'], 'demo-load')


class LocationTests(unittest.TestCase):
    """Where a cursor may live: nowhere at all, or one host's private absolute path."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unset_and_blank_both_answer_none(self):
        for environment in ({}, {anomaly_cursor.CURSOR_ENVIRONMENT: ''},
                            {anomaly_cursor.CURSOR_ENVIRONMENT: '   '}):
            with self.subTest(environment=repr(environment)):
                self.assertIsNone(anomaly_cursor.cursor_location(environment))

    def test_a_relative_path_is_refused_rather_than_defaulted(self):
        for raw in ('anomaly-cursor.json', './anomaly-cursor.json',
                    str(Path('state') / 'anomaly-cursor.json')):
            with self.subTest(raw=raw), self.assertRaises(CursorRefusal):
                anomaly_cursor.cursor_location({anomaly_cursor.CURSOR_ENVIRONMENT: raw})

    def test_an_absolute_path_is_returned_as_it_was_named(self):
        raw = str(private(self.root) / 'anomaly-cursor.json')
        self.assertEqual(anomaly_cursor.cursor_location({anomaly_cursor.CURSOR_ENVIRONMENT: raw}),
                         Path(raw))

    def test_a_traversal_inside_an_absolute_path_is_refused(self):
        raw = str(private(self.root / 'nested') / '..' / 'anomaly-cursor.json')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.cursor_location({anomaly_cursor.CURSOR_ENVIRONMENT: raw})

    def test_an_explicit_unc_or_device_form_is_refused_where_that_form_exists(self):
        """The network path shapes a Windows string can spell, refused on the platform that has them.

        Not a platform disguise: the two branches are the two truthful answers, and each runs where it
        applies. A *mapped drive letter* pointing at a share, and a POSIX NFS/SMB mount, are
        indistinguishable from a local path and are not claimed to be detected — the operator verifies
        the filesystem, because an advisory lock on a remote mount may be granted twice rather than
        fail.
        """
        for raw in ('\\\\server\\share\\anomaly-cursor.json', '//server/share/anomaly-cursor.json',
                    '\\\\.\\PhysicalDrive0', '\\\\?\\C:\\state\\anomaly-cursor.json'):
            environment = {anomaly_cursor.CURSOR_ENVIRONMENT: raw}
            if os.name == 'nt':
                with self.subTest(raw=raw), self.assertRaises(CursorRefusal):
                    anomaly_cursor.cursor_location(environment)
            else:
                # On POSIX these are ordinary (if silly) names in the current directory or under /,
                # and the absolute-path rule is what refuses them. Saying so here is the honest test.
                with self.subTest(raw=raw):
                    try:
                        located = anomaly_cursor.cursor_location(environment)
                    except CursorRefusal as refused:
                        self.assertIn('absolute', str(refused))
                    else:
                        self.assertEqual(located, Path(raw))

    def test_a_missing_parent_is_refused_and_names_the_remedy(self):
        with self.assertRaises(CursorRefusal) as refused:
            anomaly_cursor.private_parent(self.root / 'absent' / 'anomaly-cursor.json')
        self.assertIn('0700', str(refused.exception))

    def test_a_symlinked_parent_is_refused(self):
        real = private(self.root / 'real')
        link = self.root / 'link'
        try:
            make_link(link, real, directory=True)
        except SkipSymlink:
            self.skipTest('Windows withholds SeCreateSymbolicLinkPrivilege from this test run')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.private_parent(link / 'anomaly-cursor.json')

    @unittest.skipIf(os.name == 'nt', 'a POSIX mode is the only statement of group and other access')
    def test_a_parent_reachable_by_group_or_other_is_refused(self):
        shared = self.root / 'shared'
        shared.mkdir()
        os.chmod(shared, 0o755)
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.private_parent(shared / 'anomaly-cursor.json')
        os.chmod(shared, 0o700)
        self.assertEqual(anomaly_cursor.private_parent(shared / 'anomaly-cursor.json'), shared)


class WireTests(CursorFixture):
    """The property the retry contract stands on: the stored payload *is* the request body."""

    def client(self) -> tuple[JsonClient, list]:
        """Return a real ``JsonClient`` whose transport only records the bytes it was handed."""
        recorded: list = []

        def open(request, timeout=None):
            recorded.append(request)
            return Answer()

        patcher = mock.patch('urllib.request.build_opener')
        build = patcher.start()
        self.addCleanup(patcher.stop)
        build.return_value.open.side_effect = open
        return JsonClient('https://platform.example.invalid', 'x' * 32), recorded

    def test_wire_bytes_are_what_the_client_itself_sends(self):
        window, sample, finding = batch()
        client, recorded = self.client()
        client.request('POST', '/v1/events', finding)
        client.request('POST', '/v1/evidence', sample)
        self.assertEqual(recorded[0].data, anomaly_cursor.wire_bytes(finding))
        self.assertEqual(recorded[1].data, anomaly_cursor.wire_bytes(sample))
        self.assertEqual(anomaly_cursor.payload_digest(finding),
                         hashlib.sha256(anomaly_cursor.wire_bytes(finding)).hexdigest())

    def test_a_batch_survives_the_cursor_file_without_losing_a_bit(self):
        """A value that slips in the JSON round trip would be a new verdict, not a replay.

        ``1.0000000000000002`` is the float nearest above 1 that a decimal literal can name: a
        serializer that rounded it would silently change the evidence behind an incident.
        """
        document, window, sample, finding = self.with_pending(value=1.0000000000000002)
        path = self.saved(document)
        reopened = anomaly_cursor.load(path, source=SOURCE)
        pending = reopened['series']['demo-load']['pending']
        self.assertEqual(pending['sample']['value'], 1.0000000000000002)
        self.assertEqual(anomaly_cursor.wire_bytes(pending['sample']),
                         anomaly_cursor.wire_bytes(sample))
        self.assertEqual(anomaly_cursor.wire_bytes(pending['event']),
                         anomaly_cursor.wire_bytes(finding))
        client, recorded = self.client()
        client.request('POST', '/v1/events', pending['event'])
        client.request('POST', '/v1/evidence', pending['sample'])
        self.assertEqual([item.data for item in recorded],
                         [anomaly_cursor.wire_bytes(finding), anomaly_cursor.wire_bytes(sample)])

    def test_the_document_is_written_in_one_deterministic_form(self):
        path = self.saved()
        before = self.bytes_of(path)
        anomaly_cursor.save(path, anomaly_cursor.load(path, source=SOURCE))
        self.assertEqual(self.bytes_of(path), before)


class BindingTests(CursorFixture):
    """What a stored verdict is a statement about, and the edits that therefore refuse."""

    def test_the_binding_covers_every_knob_that_can_move_a_verdict(self):
        base = anomaly_cursor.series_binding(self.series())
        moved = [
            ('another resource', self.entry(resource_id=OTHER_RESOURCE)),
            ('another query', self.entry(sql=SQL.replace('avg(v)', 'max(v)'))),
            ('another season', self.entry(season='hour_of_week')),
            ('another band width', self.entry(k=5.0)),
            ('another training span', self.entry(window_days=30)),
            ('another training floor', self.entry(min_points=100)),
            ('another bucket floor', self.entry(min_per_bucket=6)),
            ('another evaluation window', self.entry(evaluation_seconds=7200)),
            ('another series id', self.entry(id='other-series')),
        ]
        for reason, entry in moved:
            with self.subTest(change=reason):
                self.assertNotEqual(anomaly_cursor.series_binding(self.resolved(entry)), base)

    def test_the_tick_interval_is_not_part_of_the_binding(self):
        """How often the producer looks cannot change what a window means, so a retune keeps its past.

        This keeps `configdrift`'s reasoning: a cursor thrown away by a harmless retune loses the
        record of what was already reported, and the producer would then anchor as though for the
        first time and start a new history over an old one.
        """
        base = anomaly_cursor.series_binding(self.series())
        # The series pins `evaluation_seconds`, so this changes only the sleep: the binding covers the
        # window that is judged, and a retune that also moved the window would have to move it.
        retuned = self.resolved(self.entry(), tick_seconds=900)
        self.assertEqual(anomaly_cursor.series_binding(retuned), base)

    def test_a_series_that_changed_underneath_the_cursor_refuses_the_round(self):
        path = self.saved()
        before = self.bytes_of(path)
        moved = self.series(k=9.0)
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.ensure_entry(anomaly_cursor.load(path, source=SOURCE), moved)
        self.assertEqual(self.bytes_of(path), before, 'a binding refusal never rewrites the cursor')

    def test_a_cursor_written_for_one_series_loads_under_a_wider_configuration(self):
        """The binding is per series, so adding a signal does not throw the other one's past away.

        This is the decision the whole-config binding was rejected for: a cursor that refused to load
        whenever the series set changed would answer an ordinary config edit by discarding every
        backlog and every owed batch in the file. An entry whose series no longer matches what is
        configured is retained and reported instead — and `tests/test_anomaly.py` covers the case of a
        series leaving the configuration.
        """
        path = self.saved()
        written = anomaly_cursor.load(path, source=SOURCE)
        first, second = self.all_series(self.entry(), self.entry(id='second-series'))
        document = anomaly_cursor.load(path, source=SOURCE)
        anomaly_cursor.ensure_entry(document, second)
        anomaly_cursor.save(path, document)
        reopened = anomaly_cursor.load(path, source=SOURCE)
        self.assertEqual(sorted(reopened['series']), ['demo-load', 'second-series'])
        self.assertEqual(reopened['series']['demo-load'], written['series']['demo-load'],
                         'the series already in the file keeps every fact it held')
        self.assertEqual(anomaly_cursor.stale_entries(reopened, ['demo-load', 'second-series']), [])
        self.assertFalse(reopened['series']['second-series']['anchor_logged'],
                         'the new series has not been anchored yet, so it owes the newest window')
        self.assertEqual(anomaly_cursor.series_binding(first),
                         reopened['series']['demo-load']['binding'])


class LoadTests(CursorFixture):
    """Every way a cursor file can fail to be trustworthy, and the bytes it must leave alone."""

    def test_an_absent_cursor_is_a_first_start_and_writes_nothing(self):
        self.assertEqual(anomaly_cursor.load(self.path(), source=SOURCE), self.fresh())
        self.assertFalse(self.path().exists())

    def tamper(self, defect: str | None = None) -> str:
        """Return one canonical cursor document carrying exactly one named defect (or none at all).

        The digest of a tampered payload is re-tallied whenever the case is not about the digest
        itself, so each case below is refused by the check it names and not by the digest guard
        happening to fire first. An unrecognised name is an assertion failure, never a silent pass.
        """
        document, window, sample, finding = self.with_pending()
        entry = json.loads(canonical(document))['series']['demo-load']
        pending = entry['pending']
        series_id, event_changed, sample_changed = 'demo-load', False, False
        served = None
        if defect == 'entry-extra-field':
            entry['written_at'] = text(END_S)
        elif defect == 'entry-missing-field':
            del entry['anchor_logged']
        elif defect == 'series-key-not-a-label':
            series_id = 'has spaces'
        elif defect == 'binding-not-a-digest':
            entry['binding'] = '00'
        elif defect == 'negative-delivered':
            entry['delivered'] = -1
        elif defect == 'counter-not-a-number':
            entry['delivered'] = '12'
        elif defect == 'counter-not-an-integer':
            entry['no_verdict'] = 1.5
        elif defect == 'anchor-not-a-flag':
            entry['anchor_logged'] = 'yes'
        elif defect == 'instant-not-canonical':
            entry['anchored_at'] = '2026-08-05'
        elif defect == 'batch-extra-key':
            pending['attempted_at'] = text(END_S)
        elif defect == 'batch-no-sample':
            pending['sample'], sample_changed = None, True
        elif defect == 'batch-not-the-owed-window':
            entry['owed_end'] = text(END_S + EVALUATION)
        elif defect == 'batch-for-an-acked-window':
            entry['last_acked_end'] = text(END_S)
        elif defect == 'counter-past-the-ceiling':
            entry['refusals'] = anomaly_cursor.MAX_COUNT + 1
        elif defect == 'served-marker-is-not-a-label':
            served = 'has spaces'
        elif defect == 'batch-another-producer':
            pending['event']['source'], event_changed = 'someone-else', True
        elif defect == 'event-names-another-window':
            pending['event']['window'] = {'start': pending['window']['start'],
                                          'end': text(END_S + EVALUATION)}
            event_changed = True
        elif defect == 'event-carries-no-evidence':
            pending['event']['evidence'], event_changed = [], True
        elif defect == 'event-pairs-another-sample':
            pending['event']['evidence'][0]['parameters']['sample_id'] = 'another-sample'
            event_changed = True
        elif defect == 'event-not-a-verdict-here-makes':
            pending['event']['kind'], event_changed = 'threshold', True
        elif defect == 'event-status-unknown':
            pending['event']['status'], event_changed = 'unknown', True
        elif defect == 'event-digest-wrong':
            pending['event_sha256'] = '0' * 64
        elif defect == 'evidence-digest-wrong':
            pending['evidence_sha256'] = '0' * 64
        elif defect == 'window-reversed':
            pending['window'] = {'start': pending['window']['end'], 'end': pending['window']['start']}
        elif defect == 'event-too-large':
            pending['event']['rule_id'], event_changed = 'anomaly.' + 'x' * 70_000, True
        elif defect == 'sample-too-large':
            pending['sample']['sample_id'], sample_changed = 's' * 4_000, True
        elif defect is None:
            pass
        else:
            raise AssertionError(f'no such cursor defect: {defect}')
        if event_changed:
            pending['event_sha256'] = digest(pending['event'])
        if sample_changed:
            pending['evidence_sha256'] = digest(pending['sample'])
        return canonical({**anomaly_cursor.empty_document(SOURCE), 'last_served': served,
                          'series': {series_id: entry}})

    def damaged(self) -> list:
        """Return the ``(what is wrong, defect name)`` pairs this producer must refuse to read."""
        return [
            ('an entry with an extra field', 'entry-extra-field'),
            ('an entry missing a field', 'entry-missing-field'),
            ('a series entry under an id that is not a label', 'series-key-not-a-label'),
            ('a binding that is not a digest', 'binding-not-a-digest'),
            ('a negative delivered count', 'negative-delivered'),
            ('a delivered count that is not a number', 'counter-not-a-number'),
            ('a count that is not a whole number', 'counter-not-an-integer'),
            ('an anchor flag that is not a flag', 'anchor-not-a-flag'),
            ('an instant in a form this writer never emits', 'instant-not-canonical'),
            ('an owed batch with an extra key', 'batch-extra-key'),
            ('an owed batch holding an event with no evidence sample', 'batch-no-sample'),
            ('an owed batch for a window other than the one owed', 'batch-not-the-owed-window'),
            ('an owed batch for a window this entry already acknowledged', 'batch-for-an-acked-window'),
            ('a counter past the ceiling the file may hold', 'counter-past-the-ceiling'),
            ('a round-robin marker that is not an identifier', 'served-marker-is-not-a-label'),
            ('an owed batch written for another producer', 'batch-another-producer'),
            ('an owed batch whose event names another window', 'event-names-another-window'),
            ('an owed batch whose event carries no evidence', 'event-carries-no-evidence'),
            ('an owed batch that pairs an event with another sample', 'event-pairs-another-sample'),
            ('an owed batch holding a verdict this producer cannot make',
             'event-not-a-verdict-here-makes'),
            ('an owed batch holding a status this producer never sends', 'event-status-unknown'),
            ('an owed batch whose event digest no longer matches', 'event-digest-wrong'),
            ('an owed batch whose evidence digest no longer matches', 'evidence-digest-wrong'),
            ('an owed window that ends before it starts', 'window-reversed'),
            ('an owed event larger than the platform accepts', 'event-too-large'),
            ('an owed sample larger than the store retains', 'sample-too-large'),
        ]

    def test_every_untrustworthy_document_is_refused_and_left_untouched(self):
        path = self.saved()
        for reason, defect in self.damaged():
            with self.subTest(refusal=reason):
                written = self.tamper(defect)
                path.write_text(written, encoding='utf-8')
                with self.assertRaises(CursorRefusal):
                    anomaly_cursor.load(path, source=SOURCE)
                self.assertEqual(self.bytes_of(path), written.encode(),
                                 'a refused cursor is never rewritten')

    def test_a_document_that_is_not_a_cursor_at_all_is_refused(self):
        for reason, raw in (('no JSON at all', 'this is not json'), ('a JSON list', '[]'),
                            ('a JSON number', '7'), ('null', 'null')):
            with self.subTest(refusal=reason):
                path = self.path()
                path.write_text(raw, encoding='utf-8')
                with self.assertRaises(CursorRefusal):
                    anomaly_cursor.load(path, source=SOURCE)

    def test_the_wrong_top_of_the_document_is_refused(self):
        """Keys, version and identity: the three ways a cursor can be somebody else's file.

        The control is the first element of the list read on its own below: every refusal here is
        about the one field that changed, because every other field is a document this producer wrote.
        """
        good = json.loads(self.tamper())
        path = self.saved(good)
        self.assertEqual(anomaly_cursor.load(path, source=SOURCE), good,
                         'control: this very document loads, so every refusal below is the one field')
        cases = [
            ('a missing top-level key', {key: value for key, value in good.items()
                                         if key != 'series'}),
            ('an extra top-level key', {**good, 'written_at': text(END_S)}),
            ('a schema version from the future', {**good, 'schema_version': 3}),
            ('a schema version that is not a number', {**good, 'schema_version': '1'}),
            # `True == 1` in Python, so an equality test alone would read a `true` in this field as
            # this producer's own version. It is not: it is somebody else guessing what the field means.
            ('a schema version that is the boolean true', {**good, 'schema_version': True}),
            ('a schema version that is the boolean false', {**good, 'schema_version': False}),
            ('another producer identity', {**good, 'source': 'someone-else'}),
            ('a producer identity that is not a label', {**good, 'source': 'has spaces'}),
        ]
        for reason, document in cases:
            with self.subTest(refusal=reason):
                path.write_text(canonical(document), encoding='utf-8')
                before = self.bytes_of(path)
                with self.assertRaises(CursorRefusal):
                    anomaly_cursor.load(path, source=SOURCE)
                self.assertEqual(self.bytes_of(path), before)

    def test_a_write_refuses_a_boolean_version_rather_than_creating_a_file_it_would_not_read(self):
        """The reviewer's probe, kept in CI: `save` may be the only thing that ran on a bad document.

        `load` would refuse `{"schema_version": true}` on the next round, so a `save` that accepted it
        would leave a cursor the producer can never open again — the state, and the operator's only
        record of what was owed, gone behind a refusal nobody can re-read.
        """
        path = self.root / 'cursor.json'
        document = anomaly_cursor.empty_document(SOURCE)
        for version in (True, False, 1.0, '1'):
            with self.subTest(version=repr(version)):
                with self.assertRaises(CursorRefusal):
                    anomaly_cursor.save(path, {**document, 'schema_version': version})
                self.assertFalse(path.exists(), 'a refused write creates nothing at all')
        anomaly_cursor.save(path, document)
        self.assertEqual(anomaly_cursor.load(path, source=SOURCE), document,
                         'and the refusal above is about the version, not about this document')

    def test_a_repeated_key_is_refused_because_which_value_is_the_record_is_not_decidable(self):
        path = self.saved()
        path.write_text('{"schema_version": 1, "source": "anomaly-test", "series": {}, '
                        '"series": {}}', encoding='utf-8')
        with self.assertRaises(CursorRefusal) as refused:
            anomaly_cursor.load(path, source=SOURCE)
        self.assertIn('repeats a key', str(refused.exception))

    def test_a_cursor_larger_than_the_bound_is_refused_before_it_is_parsed(self):
        path = self.path()
        path.write_bytes(b'{"series": "' + b'x' * anomaly_cursor.MAX_CURSOR_BYTES + b'"}')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.load(path, source=SOURCE)

    def test_a_symlinked_cursor_is_refused_rather_than_written_through(self):
        real = self.directory / 'somewhere-else.json'
        real.write_text(canonical(self.fresh()), encoding='utf-8')
        link = self.path()
        try:
            make_link(link, real)
        except SkipSymlink:
            self.skipTest('Windows withholds SeCreateSymbolicLinkPrivilege from this test run')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.load(link, source=SOURCE)
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.save(link, self.held())
        self.assertEqual(real.read_bytes(), canonical(self.fresh()).encode())

    def test_an_identity_this_producer_cannot_be_is_refused(self):
        for identity in ('', 'has spaces', 'x' * 129, None, 7):
            with self.subTest(identity=repr(identity)), self.assertRaises(CursorRefusal):
                anomaly_cursor.empty_document(identity)


class SaveTests(CursorFixture):
    """The write itself: private, atomic, whole-or-nothing, and never the author of a lock."""

    @unittest.skipIf(os.name == 'nt', 'the mode a file is created with is a POSIX statement')
    def test_the_cursor_is_written_private_and_re_secured_on_overwrite(self):
        path = self.saved()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.chmod(0o644)
        anomaly_cursor.save(path, self.held())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600,
                         'a cursor left readable by others is re-secured by the next write')

    def test_no_temporary_file_is_left_behind(self):
        path = self.saved()
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()),
                         ['anomaly-cursor.json'])

    def test_a_failure_before_the_rename_leaves_the_previous_bytes_and_no_temp(self):
        """Everything ``save`` does before the rename is revertible, and it fails loudly.

        The fsync of the temp file is the step a full disk actually trips over, and it sits on the side
        of the rename where the old file is still *the* file: the previous bytes stay installed, the
        producer keeps its memory, and the round that could not write posts nothing (pinned from the
        producer side in `tests/test_anomaly.py`).
        """
        path = self.saved()
        before = self.bytes_of(path)
        advanced = anomaly_cursor.load(path, source=SOURCE)
        anomaly_cursor.acknowledge(advanced, self.series(), window_end_s=END_S, verdict='idle')
        with mock.patch('os.fsync', side_effect=OSError('no space left on device')):
            with self.assertRaises(OSError):
                anomaly_cursor.save(path, advanced)
        self.assertEqual(self.bytes_of(path), before, 'the old cursor is still the cursor')
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()), ['anomaly-cursor.json'])

    def test_a_failure_after_the_rename_leaves_the_new_bytes_installed(self):
        """The other side of the rename, which no amount of atomicity can promise the old file back.

        POSIX fsyncs the *directory* after the rename, and a failure there happens once the new name is
        already in place. This forces exactly that ordering — the rename succeeds, the call then
        reports a failure — and pins what a caller must therefore assume: the new bytes are what any
        running process reads, and only their durability through a crash is unknown. `save`'s
        docstring and `docs/units/anomaly-cursor.md` say the same thing; a producer that reasoned "the
        old file is safe" from a failed save would be reading a promise this code does not make.
        """
        path = self.saved()
        advanced = anomaly_cursor.load(path, source=SOURCE)
        anomaly_cursor.acknowledge(advanced, self.series(), window_end_s=END_S, verdict='idle')
        real_replace = os.replace

        def renamed_then_reported_failure(source, destination):
            real_replace(source, destination)
            raise OSError('the platform reported the step after the rename as failed')

        with mock.patch('os.replace', side_effect=renamed_then_reported_failure):
            with self.assertRaises(OSError):
                anomaly_cursor.save(path, advanced)
        self.assertEqual(anomaly_cursor.load(path, source=SOURCE), advanced,
                         'the new document is installed and readable, not a half-written file')
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()), ['anomaly-cursor.json'])

    @unittest.skipIf(os.name == 'nt', 'only POSIX has a directory to fsync after a rename')
    def test_the_rename_is_followed_by_a_directory_fsync_where_the_platform_has_one(self):
        """The step with no Windows equivalent, pinned in its actual position: after the rename.

        The gate names a genuine platform feature (this code path does not exist on Windows, where the
        durability of the rename is therefore unverified rather than weaker-but-proven). It is the third
        OS gate in this suite and is listed in `docs/testing-standards.md`.
        """
        path = self.saved()
        advanced = anomaly_cursor.load(path, source=SOURCE)
        anomaly_cursor.acknowledge(advanced, self.series(), window_end_s=END_S, verdict='idle')
        events: list = []
        real_fsync, real_replace = os.fsync, os.replace

        def watching_fsync(descriptor):
            events.append('fsync')
            return real_fsync(descriptor)

        def watching_replace(source, destination):
            events.append('rename')
            return real_replace(source, destination)

        with mock.patch('os.fsync', side_effect=watching_fsync), \
                mock.patch('os.replace', side_effect=watching_replace):
            anomaly_cursor.save(path, advanced)
        self.assertEqual(events, ['fsync', 'rename', 'fsync'],
                         'the payload is fsynced, renamed once, and only then the directory')

    def test_a_refused_rename_leaves_the_previous_cursor_whole(self):
        path = self.saved()
        before = self.bytes_of(path)
        advanced = anomaly_cursor.load(path, source=SOURCE)
        anomaly_cursor.acknowledge(advanced, self.series(), window_end_s=END_S, verdict='idle')
        with mock.patch('os.replace', side_effect=OSError('rename refused')):
            with self.assertRaises(OSError):
                anomaly_cursor.save(path, advanced)
        self.assertEqual(self.bytes_of(path), before, 'a half-written cursor is not a cursor')
        self.assertEqual(sorted(item.name for item in path.parent.iterdir()),
                         ['anomaly-cursor.json'], 'our own temporary file is always cleaned up')

    def test_the_owner_lock_beside_the_cursor_is_never_touched(self):
        path = self.saved()
        lock = path.with_name(path.name + '.owner.lock')
        lock.write_bytes(b'\0')
        before = self.bytes_of(lock)
        anomaly_cursor.save(path, self.held())
        self.assertTrue(lock.exists(), 'a lock file says nothing about a live owner, so it stays')
        self.assertEqual(self.bytes_of(lock), before)

    def test_a_directory_in_the_cursor_place_is_refused(self):
        self.path().mkdir()
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.save(self.path(), self.held())

    def test_a_document_that_would_not_load_is_never_written(self):
        document = self.held()
        document['series']['demo-load']['refusals'] = -3
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.save(self.path(), document)
        self.assertFalse(self.path().exists())

    def test_a_document_larger_than_the_bound_refuses_rather_than_dropping_entries(self):
        document, window, sample, finding = self.with_pending()
        finding['rule_id'] = 'anomaly.' + 'x' * 60_000          # still under the per-payload ceiling
        document['series']['demo-load']['pending']['event']['rule_id'] = finding['rule_id']
        document['series']['demo-load']['pending']['event_sha256'] = digest(finding)
        self.assertLess(len(anomaly_cursor.wire_bytes(finding)), anomaly_cursor.MAX_EVENT_BYTES)
        with mock.patch.object(anomaly_cursor, 'MAX_CURSOR_BYTES', 4096):
            with self.assertRaises(CursorRefusal) as refused:
                anomaly_cursor.save(self.path(), document)
        self.assertIn('refuses rather than dropping entries', str(refused.exception))
        self.assertFalse(self.path().exists())


class WindowArithmeticTests(CursorFixture):
    """Where the next window is — which is the whole difference between resuming and forgetting."""

    def test_a_window_whose_read_failed_is_still_owed_hours_later(self):
        """Beginning a window is a durable fact, or a failed read becomes a silently skipped hour.

        No payload exists for a window whose verdict was never computed, so nothing here can be replayed
        — but the window itself must not be lost. This is the one case where the next round **should**
        re-read the store: nothing was ever promised about it, so a fresh verdict is not a changed one.
        """
        document = self.held()
        series = self.series()
        anomaly_cursor.owe(document, series, window_end_s=END_S)
        reopened = anomaly_cursor.load(self.saved(document), source=SOURCE)
        state = reopened['series']['demo-load']
        self.assertEqual(state['owed_end'], utc_text(dt.datetime.fromtimestamp(END_S, dt.timezone.utc)))
        self.assertIsNone(state['pending'], 'an attempt is not a delivery owed')
        for hours in (1, 5, 30):
            with self.subTest(hours=hours):
                self.assertEqual(anomaly_cursor.next_window_end(state, now_s=END_S + hours * EVALUATION,
                                                                evaluation=EVALUATION), END_S,
                                 'the owed window is the one it began, whatever the clock now says')
                self.assertEqual(anomaly_cursor.lag_windows(state, now_s=END_S + hours * EVALUATION,
                                                            evaluation=EVALUATION), hours + 1)

    def test_an_owed_attempt_cannot_be_jumped_over_by_a_newer_window(self):
        document = self.held()
        series = self.series()
        anomaly_cursor.owe(document, series, window_end_s=END_S)
        window, sample, finding = batch()
        with self.subTest(refusal='acknowledging a newer window'):
            with self.assertRaises(CursorRefusal):
                anomaly_cursor.acknowledge(document, series, window_end_s=END_S + EVALUATION,
                                          verdict='idle')
        with self.subTest(refusal='beginning a verdict for a newer window'):
            with self.assertRaises(CursorRefusal):
                anomaly_cursor.begin(document, series,
                                     window=anomaly_cursor.window_text(END_S + EVALUATION, EVALUATION),
                                     sample=sample, event=finding)
        with self.subTest(refusal='owing a second window on top of the first'):
            with self.assertRaises(CursorRefusal):
                anomaly_cursor.owe(document, series, window_end_s=END_S + EVALUATION)
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        self.assertIsNone(document['series']['demo-load']['owed_end'],
                         'the window it names clears the debt it names, and no other')
        self.assertEqual(anomaly_cursor.next_window_end(document['series']['demo-load'],
                                                        now_s=END_S + EVALUATION,
                                                        evaluation=EVALUATION), END_S + EVALUATION)

    def test_an_attempt_at_or_behind_the_cursor_is_refused(self):
        document = self.held()
        series = self.series()
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.owe(document, series, window_end_s=END_S)
        anomaly_cursor.owe(document, series, window_end_s=END_S + EVALUATION)

    def test_a_batch_is_always_the_window_that_is_owed(self):
        document, window, _sample, _finding = self.with_pending()
        self.assertEqual(document['series']['demo-load']['owed_end'], window['end'])

    def test_the_first_start_owes_the_newest_completed_window_and_nothing_before_it(self):
        state = anomaly_cursor.ensure_entry(self.fresh(), self.series())
        self.assertEqual(anomaly_cursor.next_window_end(state, now_s=END_S + 1800,
                                                        evaluation=EVALUATION), END_S)
        self.assertEqual(anomaly_cursor.lag_windows(state, now_s=END_S + 1800,
                                                    evaluation=EVALUATION), 1)

    def test_an_unaligned_now_never_judges_a_window_that_has_not_closed(self):
        self.assertEqual(anomaly_cursor.align_end(now_s=END_S + 3599, evaluation=EVALUATION), END_S)
        self.assertEqual(anomaly_cursor.align_end(now_s=END_S, evaluation=EVALUATION), END_S)

    def test_a_series_the_file_has_never_seen_is_anchored_by_the_clock_and_by_nothing_else(self):
        """The durable anomaly cursor's first-start rule, stated as the per-series question it is.

        The cursor holds no shared "where the producer stands" value on purpose: a series added to a
        file whose siblings are eight windows deep is not handed their backlog, and a series added to
        an empty file is not treated differently from one added to a busy one. The newest completed
        window is the whole answer, and the first-start WARNING is what says the older history of
        *this* series was never judged.
        """
        for document in (self.fresh(), self.held()):
            if document['series']:
                anomaly_cursor.acknowledge(document, self.series(),
                                           window_end_s=END_S - 8 * EVALUATION, verdict='idle')
            with self.subTest(siblings=len(document['series'])):
                self.assertEqual(anomaly_cursor.align_end(now_s=END_S + 1800,
                                                          evaluation=EVALUATION), END_S)
                self.assertEqual(anomaly_cursor.align_end(now_s=END_S, evaluation=EVALUATION), END_S)
                self.assertEqual(
                    anomaly_cursor.window_text(anomaly_cursor.align_end(now_s=END_S + 1800,
                                                                        evaluation=EVALUATION),
                                               EVALUATION)['end'], text(END_S))

    def test_a_sibling_s_debt_is_never_asked_about_when_anchoring(self):
        """The arithmetic that answers the anchor question reads the clock, not the other entries.

        :func:`anomaly_cursor.next_window_end` is the only window question asked about an entry that
        has begun, and it takes one entry plus the clock: nothing in this module compares one series'
        owed window to another's, which is what keeps a new series out of a stranger's backlog.
        """
        document = self.held()
        anomaly_cursor.acknowledge(document, self.series(), window_end_s=END_S - 8 * EVALUATION,
                                   verdict='idle')
        self.assertEqual(
            anomaly_cursor.next_window_end(document['series']['demo-load'], now_s=END_S,
                                           evaluation=EVALUATION), END_S - 7 * EVALUATION,
            'a series with history resumes its own ascending walk')
        self.assertEqual(
            anomaly_cursor.next_window_end(anomaly_cursor.ensure_entry(
                document, {**self.series(), 'id': 'newcomer'}),
                now_s=END_S, evaluation=EVALUATION), END_S,
            'a brand-new entry is anchored by the clock: a sibling eight windows back is not its past')

    def test_catch_up_walks_ascending_and_contiguously_then_stops(self):
        document = self.held()
        series = self.series()
        state = document['series']['demo-load']
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        for step in range(1, 5):
            self.assertEqual(anomaly_cursor.next_window_end(state, now_s=END_S + 4 * EVALUATION,
                                                            evaluation=EVALUATION),
                             END_S + step * EVALUATION)
            anomaly_cursor.acknowledge(document, series, window_end_s=END_S + step * EVALUATION,
                                       verdict='idle')
        self.assertIsNone(anomaly_cursor.next_window_end(state, now_s=END_S + 4 * EVALUATION,
                                                        evaluation=EVALUATION))
        self.assertEqual(anomaly_cursor.lag_windows(state, now_s=END_S + 4 * EVALUATION,
                                                    evaluation=EVALUATION), 0)

    def test_a_backlog_resumes_at_the_cursor_however_far_the_clock_has_moved(self):
        """The defect this cursor exists to close: five days down must not become one window judged.

        A resume point of ``max(last_end + interval, now)`` would read as "caught up" and drop every
        window in between. The assertion below is that the clock cannot move the resume point at all —
        it can only say whether more windows have closed since it.
        """
        document = self.held()
        series = self.series()
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        state = document['series']['demo-load']
        for hours in (1, 12, 24 * 7):
            with self.subTest(hours_later=hours):
                self.assertEqual(anomaly_cursor.next_window_end(state, now_s=END_S + hours * 3600,
                                                                evaluation=EVALUATION),
                                 END_S + EVALUATION)
        self.assertEqual(anomaly_cursor.lag_windows(state, now_s=END_S + 24 * 7 * 3600,
                                                    evaluation=EVALUATION), 24 * 7)
        self.assertIsNone(anomaly_cursor.next_window_end(state, now_s=END_S, evaluation=EVALUATION))

    def test_an_owed_batch_is_always_the_next_thing_owed(self):
        document, window, sample, finding = self.with_pending()
        state = document['series']['demo-load']
        self.assertEqual(anomaly_cursor.next_window_end(state, now_s=END_S + 9 * EVALUATION,
                                                        evaluation=EVALUATION), END_S)
        self.assertEqual(anomaly_cursor.lag_windows(state, now_s=END_S + 9 * EVALUATION,
                                                    evaluation=EVALUATION), 10)

    def test_only_a_whole_positive_number_of_seconds_is_a_window(self):
        for bad in (0, -1, 3600.5, True, None):
            with self.subTest(evaluation=repr(bad)), self.assertRaises(CursorRefusal):
                anomaly_cursor.align_end(now_s=END_S, evaluation=bad)

    def test_the_window_pair_is_the_one_the_event_factory_will_be_given(self):
        self.assertEqual(anomaly_cursor.window_text(END_S, EVALUATION),
                         {'start': text(END_S - EVALUATION), 'end': text(END_S)})


class PendingTests(CursorFixture):
    """The owed batch: written before the POST, cleared only by the window it names."""

    def test_an_owed_batch_carries_the_digest_of_what_will_be_sent(self):
        document, window, sample, finding = self.with_pending()
        pending = document['series']['demo-load']['pending']
        self.assertEqual(pending['event_sha256'], digest(finding))
        self.assertEqual(pending['evidence_sha256'], digest(sample))
        self.assertEqual(pending['window'], window)

    def test_a_second_batch_for_the_same_series_is_refused(self):
        document, window, sample, finding = self.with_pending()
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.begin(document, self.series(), window=window, sample=sample, event=finding)

    def test_an_acknowledgement_must_name_the_owed_window(self):
        document, window, sample, finding = self.with_pending()
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.acknowledge(document, self.series(), window_end_s=END_S + EVALUATION,
                                       verdict='delivered')

    def test_an_event_verdict_needs_the_batch_it_describes(self):
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.acknowledge(self.held(), self.series(), window_end_s=END_S,
                                       verdict='delivered')

    def test_nothing_is_acked_at_or_behind_the_cursor(self):
        document = self.held()
        series = self.series()
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S + EVALUATION, verdict='idle')

    def test_an_unknown_verdict_word_is_refused(self):
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.acknowledge(self.held(), self.series(), window_end_s=END_S,
                                       verdict='probably-fine')

    def test_the_anchor_is_the_first_window_ever_judged_and_never_moves(self):
        document = self.held()
        series = self.series()
        self.assertFalse(document['series']['demo-load']['anchor_logged'])
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='idle')
        anchored = document['series']['demo-load']['anchored_at']
        self.assertEqual(anchored, text(END_S))
        anomaly_cursor.mark_anchored(document, series)
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S + EVALUATION, verdict='idle')
        self.assertEqual(document['series']['demo-load']['anchored_at'], anchored,
                         'a later window does not move the anchor of the first one')

    def test_verdicts_are_counted_apart_from_deliveries(self):
        document, window, sample, finding = self.with_pending()
        series = self.series()
        anomaly_cursor.note_refusal(document, series)
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S, verdict='delivered')
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S + EVALUATION, verdict='idle')
        anomaly_cursor.acknowledge(document, series, window_end_s=END_S + 2 * EVALUATION,
                                   verdict='insufficient')
        later = END_S + 3 * EVALUATION
        _, recovery, closing = batch(end_s=later, status='resolved', sample_id='sample-2')
        anomaly_cursor.begin(document, series, window={'start': text(later - EVALUATION),
                                                       'end': text(later)},
                             sample=recovery, event=closing)
        anomaly_cursor.acknowledge(document, series, window_end_s=later, verdict='recovered')
        entry = document['series']['demo-load']
        self.assertEqual((entry['delivered'], entry['no_verdict'], entry['refusals']), (2, 2, 1))
        self.assertEqual(entry['last_acked_end'], text(later))

    def test_a_removed_series_keeps_its_bytes_and_is_reported_as_owed(self):
        """Nothing here deletes or acks a batch for a series the configuration no longer names."""
        document, window, sample, finding = self.with_pending()
        path = self.saved(document)
        reopened = anomaly_cursor.load(path, source=SOURCE)
        self.assertEqual(anomaly_cursor.stale_entries(reopened, []), ['demo-load'])
        self.assertEqual(anomaly_cursor.unresolved_pending(reopened, []), ['demo-load'])
        self.assertEqual(anomaly_cursor.stale_entries(reopened, ['demo-load']), [])
        self.assertEqual(anomaly_cursor.unresolved_pending(reopened, ['demo-load']), [])
        self.assertEqual(reopened, document)


class EntryBoundTests(CursorFixture):
    """The file is capped, and going past the cap stops the producer instead of trimming its memory."""

    def filled(self, entries: int) -> dict:
        document = self.fresh()
        for position in range(entries):
            document['series'][f'kept-{position}'] = {
                'binding': digest(['kept', position]), 'last_acked_end': None, 'anchored_at': None,
                'anchor_logged': False, 'owed_end': None, 'delivered': 0, 'no_verdict': 0,
                'refusals': 0, 'pending': None}
        return document

    def test_adding_past_the_entry_bound_refuses_and_adds_nothing(self):
        document = self.filled(anomaly_cursor.MAX_ENTRIES)
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.ensure_entry(document, self.series())
        self.assertEqual(len(document['series']), anomaly_cursor.MAX_ENTRIES)

    def test_a_document_already_past_the_bound_refuses_to_load(self):
        document = self.filled(anomaly_cursor.MAX_ENTRIES + 1)
        path = self.path('oversized.json')
        path.write_text(canonical(document), encoding='utf-8')
        with self.assertRaises(CursorRefusal):
            anomaly_cursor.load(path, source=SOURCE)

    def test_the_stored_document_is_one_canonical_line(self):
        path = self.saved()
        written = self.bytes_of(path)
        self.assertEqual(written, canonical(anomaly_cursor.load(path, source=SOURCE)).encode())
        self.assertNotIn(b'\n', written)
        self.assertTrue(written.startswith(b'{"last_served":'), 'keys sorted, not pretty-printed')


if __name__ == '__main__':
    unittest.main()
