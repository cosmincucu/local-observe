"""Sigma compiler / notification budget: the rule pack's `shipped`/`measured`/`unmeasured` triple on the operator surface.

The smallest honest increment the decision allows. notification budget's precision *budget* needs a per-rule
false-positive count measured over a population, and no rule in this tree has one — so what this file
proves is the number that does exist and does not need inventing: how much of the pack has ever been
counted at all. One function pair, asserted from both ends, and since overview sigma producer from the middle too:

* `sigma_runner.measurement_report` + `measurement_signal` (the producer's shape),
* `platform/overview_worker.py` (the one writer that puts that shape into the published document, and
  the reason an unreadable pack publishes no key at all), and
* `platform/overview.py` (the reader that refuses any other shape, and nulls what has aged out).

Four properties, each named in a test below: an absent observation is `unknown` with three nulls and
**never** a healthy zero (portal layout's rule, the same one `jobs` and `model` live by); a malformed observation
is refused whole rather than partly trusted; a real report off the real tree survives the round trip
unchanged, which is what stops the two sides renaming a key in silence; and the writer withholds the
key — with one WARNING naming the path — whenever the pack it was pointed at cannot be read, including
since map guard and artifact cap the case of one artifact too large to open.

Nothing here pages, opens or resolves anything. The signal reports; `platform/state.py` decides what is
open (incident and action state), and the runner's container healthcheck stays the age of its cursor.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from local_observe.platform.overview import overview, signal
from local_observe.platform import sigma_runner

ROOT = Path(__file__).resolve().parents[1]
COMPILED = ROOT / 'examples' / 'sigma' / 'compiled'
NOW = dt.datetime(2026, 9, 10, 12, tzinfo=dt.timezone.utc)


class Store:
    """Enough of `platform.state.Store` for one overview read: the counters, and no `path` to count.

    The same shape `tests/test_overview.py` uses. With no `path` attribute, `suppressed_deliveries`
    answers None, which is this file's subject rather than an obstacle: an unreadable number is None
    here, exactly as the sigma triple is.
    """

    def status(self) -> dict:
        return {'incidents': {'open': 1}, 'actions': {'pending': 0},
                'notifications': {'pending': 0, 'sending': 0, 'dead': 0}}


class ReaderTests(unittest.TestCase):
    """What `/v1/overview` answers for each state a `sigma` observation can arrive in."""

    def published(self, root: Path) -> Path:
        """Write one observation document the way the overview writer does: one signal, one file."""
        path = root / 'overview.json'
        path.write_text(json.dumps({'schema_version': 1, 'signals': {'sigma': self.item()}}),
                        encoding='utf-8')
        return path

    def item(self, **overrides) -> dict:
        report = {'shipped': 3, 'measured': 1, 'unmeasured': 2, 'headline': '3 rules shipped, 2 unmeasured'}
        return sigma_runner.measurement_signal(report, now=NOW, **overrides)

    def read(self, path):
        return overview(Store(), path, now=NOW)

    def test_no_observation_is_unknown_with_three_nulls_and_never_a_zero(self) -> None:
        """The state every deployment is in today: no producer, so no number, and no all-clear either."""
        with tempfile.TemporaryDirectory() as directory:
            # (a) no observation file at all, (b) a file that carries the other signals and not this one.
            value = overview(Store(), Path(directory) / 'absent.json', now=NOW)
            self.assertEqual((value['sigma_shipped'], value['sigma_measured'], value['sigma_unmeasured']),
                             (None, None, None), 'an absent pack may not be read as an empty one')
            self.assertEqual(value['sigma_display'], 'Unknown')
            self.assertEqual(value['sigma_status'], 'unknown')
            self.assertEqual(value['signals']['sigma']['source'], 'not configured')
            published = Path(directory) / 'overview.json'
            published.write_text(json.dumps({'schema_version': 1, 'signals': {
                'jobs': {'status': 'disabled', 'value': None, 'observed_at': NOW.isoformat(),
                         'max_age_seconds': 120, 'source': 'job monitor not enrolled'},
                'model': {'status': 'disabled', 'value': None, 'observed_at': NOW.isoformat(),
                          'max_age_seconds': 120, 'source': 'ai component not deployed'}}}),
                                 encoding='utf-8')
            value = self.read(published)
            self.assertIsNone(value['sigma_unmeasured'])
            self.assertEqual(value['signals']['sigma']['source'], 'observation unavailable',
                             'a producer that published without this signal is a gap, not a zero')

    def test_a_published_pack_shows_its_triple_and_its_own_sentence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            value = self.read(self.published(Path(directory)))
            self.assertEqual((value['sigma_shipped'], value['sigma_measured'], value['sigma_unmeasured']),
                             (3, 1, 2))
            self.assertEqual(value['sigma_display'], '3 rules shipped, 2 unmeasured')
            self.assertEqual(value['sigma_status'], 'degraded',
                             'a rule nobody counted keeps the tile amber; that is the whole claim')
            self.assertEqual(value['sigma_scope'], sigma_runner.MEASUREMENT_SOURCE,
                             'the scope line names what was counted, as `jobs_scope` names its limit')

    def test_a_counted_pack_is_healthy_and_a_disabled_one_says_so(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            healthy = sigma_runner.measurement_signal({'shipped': 2, 'measured': 2, 'unmeasured': 0,
                                                       'headline': '2 rules shipped, 0 unmeasured'},
                                                      now=NOW)
            self.assertEqual(healthy['status'], 'healthy')
            path = root / 'overview.json'
            path.write_text(json.dumps({'schema_version': 1, 'signals': {'sigma': healthy}}),
                            encoding='utf-8')
            value = self.read(path)
            self.assertEqual((value['sigma_shipped'], value['sigma_measured'], value['sigma_unmeasured']),
                             (2, 2, 0))
            self.assertEqual(value['sigma_status'], 'healthy')
            disabled = {**healthy, 'status': 'disabled', 'source': 'no rule pack deployed'}
            path.write_text(json.dumps({'schema_version': 1, 'signals': {'sigma': disabled}}),
                            encoding='utf-8')
            value = self.read(path)
            self.assertIsNone(value['sigma_shipped'], 'a disabled pack carries no counts, even a valid one')
            self.assertEqual(value['sigma_display'], 'Disabled')

    def test_a_measurement_past_its_own_bound_is_nulled_rather_than_repeated(self) -> None:
        """The freshness bound belongs to the observation, so an old pack reads as no pack."""
        with tempfile.TemporaryDirectory() as directory:
            path = self.published(Path(directory))
            value = overview(Store(), path, now=NOW + dt.timedelta(seconds=3601))
            self.assertIsNone(value['sigma_unmeasured'])
            self.assertEqual(value['sigma_status'], 'stale')
            self.assertEqual(value['sigma_display'], 'Stale')
            fresh = overview(Store(), path, now=NOW + dt.timedelta(seconds=3599))
            self.assertEqual(fresh['sigma_unmeasured'], 2, 'the bound is the one stated, not a guess')

    def test_a_malformed_observation_is_refused_whole(self) -> None:
        """Nothing here coerces: a triple that cannot be believed is `unknown`, never repaired."""
        good = {'shipped': 3, 'measured': 1, 'unmeasured': 2, 'headline': '3 rules shipped, 2 unmeasured'}
        broken: list = [3, 'three', None, [], {'shipped': 3, 'measured': 1, 'unmeasured': 2},
                        {**good, 'extra': 1}, {k: v for k, v in good.items() if k != 'unmeasured'},
                        {**good, 'shipped': '3'}, {**good, 'measured': 1.5}, {**good, 'measured': True},
                        {**good, 'measured': -1}, {**good, 'shipped': 4}, {**good, 'headline': ''},
                        {**good, 'headline': 'x' * 121}]
        for value in broken:
            with self.subTest(value=repr(value)[:36]):
                item = {**self.item(), 'value': value}
                self.assertEqual(signal(item_document(item), 'sigma', NOW)['status'], 'unknown')
                self.assertIsNone(signal(item_document(item), 'sigma', NOW)['value'])
        for state in ('healthy_zero', '', 'firing'):
            with self.subTest(status=state):
                self.assertEqual(signal(item_document({**self.item(), 'status': state}),
                                        'sigma', NOW)['status'], 'unknown')


class ProducerTests(unittest.TestCase):
    """`measurement_signal` — the pack's own numbers, in the shape the reader will accept."""

    def report(self, **overrides) -> dict:
        report = {'shipped': 2, 'measured': 0, 'unmeasured': 2, 'headline': '2 rules shipped, 2 unmeasured',
                  'rules': []}
        return {**report, **overrides}

    def test_the_signal_is_the_report_without_its_per_rule_detail(self) -> None:
        item = sigma_runner.measurement_signal(self.report(), now=NOW)
        self.assertEqual(item['value'], {'shipped': 2, 'measured': 0, 'unmeasured': 2,
                                        'headline': '2 rules shipped, 2 unmeasured'})
        self.assertEqual(item['observed_at'], sigma_runner.utc_text(NOW))
        self.assertEqual(item['max_age_seconds'], sigma_runner.MEASUREMENT_MAX_AGE_SECONDS)
        self.assertEqual(item['status'], 'degraded')
        self.assertEqual(sorted(item), ['max_age_seconds', 'observed_at', 'source', 'status', 'value'])
        self.assertEqual(sorted(item['value']), ['headline', 'measured', 'shipped', 'unmeasured'],
                         'the per-rule detail is a log line and a command output, not a portal field')

    def test_a_report_it_cannot_honestly_publish_is_a_refusal(self) -> None:
        for report in ({'shipped': 2, 'measured': 0, 'unmeasured': 2},
                       {'shipped': 3, 'measured': 0, 'unmeasured': 2, 'headline': 'x'},
                       {'shipped': 2, 'measured': 1, 'unmeasured': 1, 'headline': ''},
                       {'shipped': 2, 'measured': None, 'unmeasured': 2, 'headline': 'x'},
                       {'shipped': 2, 'measured': -1, 'unmeasured': 3, 'headline': 'x'},
                       {'shipped': 2.0, 'measured': 0, 'unmeasured': 2, 'headline': 'x'}):
            with self.subTest(report=sorted(report)[:2]):
                with self.assertRaises(ValueError):
                    sigma_runner.measurement_signal(report, now=NOW)
        for source in ('', '   ', None):
            with self.subTest(source=repr(source)):
                with self.assertRaises(ValueError):
                    sigma_runner.measurement_signal(self.report(), now=NOW, source=source)

    def test_the_real_pack_round_trips_through_the_reader_unchanged(self) -> None:
        """The pair test: producer's numbers, producer's shape, reader's answer, nothing invented.

        Run over the committed artifacts, so it moves when a rule ships or is measured — which is the
        point. `2 rules shipped, 2 unmeasured` is also asserted by name in
        `tests/test_sigma_rules.py::MeasurementHonestyTests`; the value of this test is the arrow, not
        the number.
        """
        report = sigma_runner.measurement_report(sorted(COMPILED.glob('*.json')))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'overview.json'
            item = sigma_runner.measurement_signal(report, now=NOW)
            path.write_text(json.dumps({'schema_version': 1, 'signals': {'sigma': item}}), encoding='utf-8')
            value = overview(Store(), path, now=NOW)
            self.assertEqual(value['sigma_shipped'], report['shipped'])
            self.assertEqual(value['sigma_measured'], report['measured'])
            self.assertEqual(value['sigma_unmeasured'], report['unmeasured'])
            self.assertEqual(value['sigma_display'], report['headline'])
            self.assertEqual(value['sigma_status'], 'degraded',
                             'the shipped pack carries no measured rate, so the tile is not green')


class PublishedDocumentTests(unittest.TestCase):
    """overview sigma producer: what the one writer of that document publishes, with the key present and absent.

    `overview_worker.publish` is the only producer of this file in the tree, so the states a deployment
    can be in are decided there: no key (no pack configured), a readable directory (a real triple), or a
    pack that cannot be read (still no key, plus one WARNING naming the path). The third is the one that
    matters: an unreadable pack must reach the reader as *no observation*, because the alternative is a
    `0` that reads as "counted, and quiet".
    """

    def config(self, root: Path, **extra) -> dict:
        """A minimal worker configuration whose mandatory `jobs` signal is an unreadable fixture.

        The cursor file is deliberately missing: `jobs` then publishes `unknown`, which is not this
        file's subject and must not be entangled with the `sigma` branch under test.
        """
        return {'output': str(root / 'state.json'), 'jobs_cursor': str(root / 'missing.json'),
                'expected_jobs': ['test'], **extra}

    def publish(self, root: Path, **extra) -> dict:
        """Run one tick and hand back the document that landed on disk."""
        from local_observe.platform.overview_worker import publish
        publish(self.config(root, **extra), now=NOW)
        return json.loads((root / 'state.json').read_text(encoding='utf-8'))

    def warn_once(self, root: Path, **extra) -> tuple:
        """Publish expecting the `sigma` branch to refuse, and return (document, warning record)."""
        from local_observe.platform.overview_worker import publish
        with self.assertLogs('local_observe.platform.overview_worker', 'WARNING') as captured:
            publish(self.config(root, **extra), now=NOW)
        document = json.loads((root / 'state.json').read_text(encoding='utf-8'))
        self.assertEqual([record.getMessage() for record in captured.records],
                         ['Sigma observation not published'],
                         'one refusal is one operator line: not a stack trace, and not silence')
        return document, captured.records[0]

    def test_an_absent_key_publishes_two_signals_and_the_reader_says_unknown(self) -> None:
        """The state `minimal` and `standard` live in: no key, two signals, and no number invented.

        Pinned before overview sigma producer as
        `test_the_writer_still_publishes_two_signals_and_the_reader_says_unknown`;
        the third producer exists now, so what this test guards is that it stayed opt-in — a deployment
        that configures no rule pack publishes exactly what it published on 2026-09-10.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self.publish(root)
            self.assertEqual(sorted(document['signals']), ['jobs', 'model'],
                             'no sigma_artifacts key means no sigma key in the document')
            value = overview(Store(), root / 'state.json', now=NOW)
            self.assertIsNone(value['sigma_unmeasured'])
            self.assertEqual(value['sigma_display'], 'Unknown')

    def test_a_configured_directory_publishes_the_triple_the_reader_renders(self) -> None:
        """The whole arrow: committed artifacts, this writer, the document, `/v1/overview`'s fields."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self.publish(root, sigma_artifacts=str(COMPILED))
            self.assertEqual(sorted(document['signals']), ['jobs', 'model', 'sigma'])
            item = document['signals']['sigma']
            self.assertEqual(item['observed_at'], sigma_runner.utc_text(NOW))
            self.assertEqual(item['max_age_seconds'], sigma_runner.MEASUREMENT_MAX_AGE_SECONDS)
            self.assertEqual(item['source'], sigma_runner.MEASUREMENT_SOURCE)
            self.assertEqual(item['value'], {'shipped': 2, 'measured': 0, 'unmeasured': 2,
                                            'headline': '2 rules shipped, 2 unmeasured'},
                             'the pack this test was written against; when a rule ships or is measured '
                             'the number moves here and in tests/test_sigma_rules.py together')
            value = overview(Store(), root / 'state.json', now=NOW)
            self.assertEqual(value['sigma_shipped'], 2)
            self.assertEqual((value['sigma_measured'], value['sigma_unmeasured']), (0, 2))
            self.assertEqual(value['sigma_display'], '2 rules shipped, 2 unmeasured')
            self.assertEqual(value['sigma_status'], 'degraded',
                             'landing the producer does not turn the tile green')
            self.assertEqual(document['signals']['jobs']['status'], 'unknown',
                             'the other two signals are written as before, unreadable cursor included')

    def test_reading_a_rule_pack_opens_no_socket(self) -> None:
        """The triple is a read of reviewed files: no health probe, no store client, no subprocess."""
        from unittest import mock
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch('local_observe.platform.overview_worker.urllib.request.build_opener') as opener:
                document = self.publish(root, sigma_artifacts=str(COMPILED))
            opener.assert_not_called()
            self.assertIn('sigma', document['signals'])

    def test_an_unreadable_pack_publishes_no_key_and_warns_once(self) -> None:
        """Every way a pack can fail to be readable ends in the same place: no key, one line, no zero."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / 'empty'
            empty.mkdir()
            partly = root / 'partly'
            partly.mkdir()
            shutil.copyfile(sorted(COMPILED.glob('*.json'))[0], partly / 'good.json')
            (partly / 'broken.json').write_text('{}', encoding='utf-8')
            a_file = root / 'not-a-directory.json'
            a_file.write_text('{}', encoding='utf-8')
            oversized = root / 'oversized'
            oversized.mkdir()
            good = sorted(COMPILED.glob('*.json'))[0]
            shutil.copyfile(good, oversized / 'good.json')
            (oversized / 'huge.json').write_bytes(good.read_bytes() + b' ' * sigma_runner.ARTIFACT_MAX_BYTES)
            cases: list = [str(root / 'absent'), str(a_file), '', '   ', 8080,
                           [str(COMPILED)], str(empty), str(partly), str(oversized)]
            for configured in cases:
                with self.subTest(configured=repr(configured)[:40]):
                    document, record = self.warn_once(root, sigma_artifacts=configured)
                    self.assertEqual(sorted(document['signals']), ['jobs', 'model'],
                                     'a pack that cannot be read is no observation, never a zero')
                    value = overview(Store(), root / 'state.json', now=NOW)
                    self.assertIsNone(value['sigma_unmeasured'])
                    self.assertEqual(value['sigma_display'], 'Unknown')
                    if isinstance(configured, str) and configured.strip():
                        self.assertIn(Path(configured).name, record.sigma_artifacts,
                                      'the line names the path the operator has to fix')
                    self.assertTrue(record.reason, 'and says on what authority nothing was published')

    def test_an_oversized_artifact_is_refused_for_its_size_alone(self):
        """map guard and artifact cap: the byte cap is a third way a pack refuses to be read, and the operator line has to say so.

        The file is a real committed artifact padded with trailing whitespace, which `json.loads` accepts
        — so the same bytes publishing a triple unpadded and withholding one padded proves it was the
        bound that refused, not the content. The WARNING's reason then carries the bound and the size,
        which is what tells an operator to look at the mount rather than at the rule.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            packed = sorted(COMPILED.glob('*.json'))[0].read_bytes()
            for name, tail in (('clean', b''), ('padded', b' ' * sigma_runner.ARTIFACT_MAX_BYTES)):
                with self.subTest(pack=name):
                    pack = root / name
                    pack.mkdir()
                    (pack / 'rule.json').write_bytes(packed + tail)
                    if tail:
                        document, record = self.warn_once(root, sigma_artifacts=str(pack))
                        self.assertEqual(sorted(document['signals']), ['jobs', 'model'],
                                         'one oversized artifact withholds the whole pack, not one rule')
                        self.assertIn('ValueError', record.reason,
                                      'a bound refusal, so it is not reported as a parse error')
                        self.assertIn(str(sigma_runner.ARTIFACT_MAX_BYTES), record.reason,
                                      'the line names the bound the file crossed')
                    else:
                        self.assertIn('sigma', self.publish(root, sigma_artifacts=str(pack))['signals'],
                                      'the same bytes under the bound are a readable pack')

    def test_an_explicit_null_is_read_as_the_absent_key_it_duplicates(self) -> None:
        """`"sigma_artifacts": null` publishes two signals and no warning, exactly like `"ai": null`.

        The worker reads both keys with `config.get(...)`, so a null and an absent key are one state;
        inventing a distinction here would be a second rule for `ai` that `model_signal` does not have.
        An operator who writes the key with no value gets `unknown` on the tile, which is the truth.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = self.publish(root, sigma_artifacts=None)
            self.assertEqual(sorted(document['signals']), ['jobs', 'model'])
            self.assertEqual(overview(Store(), root / 'state.json', now=NOW)['sigma_display'], 'Unknown')

    def test_the_artifact_bound_is_enforced_before_anything_is_counted(self) -> None:
        """The 64 bound is on the count, not the bytes, and crossing it is a refusal that says how far.

        Sixty-four unreadable files still pass the resolver — what it limits is how many files one tick
        opens — while their contents are refused by `sigma_runner.artifact()`. The two halves are
        asserted apart so a change to one cannot silently relax the other.
        """
        from local_observe.platform.overview_worker import SIGMA_ARTIFACT_MAX, sigma_artifact_paths
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            at_limit = root / 'at-limit'
            at_limit.mkdir()
            for index in range(SIGMA_ARTIFACT_MAX):
                (at_limit / f'rule-{index:03d}.json').write_text('{}', encoding='utf-8')
            self.assertEqual(len(sigma_artifact_paths(str(at_limit))), SIGMA_ARTIFACT_MAX)
            over = root / 'over'
            over.mkdir()
            for index in range(SIGMA_ARTIFACT_MAX + 1):
                (over / f'rule-{index:03d}.json').write_text('{}', encoding='utf-8')
            with self.assertRaises(ValueError):
                sigma_artifact_paths(str(over))
            document, record = self.warn_once(root, sigma_artifacts=str(over))
            self.assertEqual(sorted(document['signals']), ['jobs', 'model'])
            self.assertIn(str(SIGMA_ARTIFACT_MAX + 1), record.reason,
                          'the warning names the count it refused, not just that it refused')


def item_document(item: dict) -> dict:
    """A published document holding one `sigma` signal, for the reader tests above."""
    return {'schema_version': 1, 'signals': {'sigma': item}}


if __name__ == '__main__':
    unittest.main()
