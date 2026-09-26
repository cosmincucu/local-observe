"""The investigation component bundle: assembled from stored evidence, bounded, and silent about what it cannot show.

The four properties this file exists to keep, in the order the component brief states them
(`docs/remediation/briefs/components/investigation component-rca.md`, designs 2 and 3, plus the rca member re-point):

* every telemetry fact comes out of the platform's own evidence table through
  `platform/query.py::reauthorise` — the fake store below exposes *that one method and no other*, so a
  bundle that reached for a query builder or a transport would fail with `AttributeError` here rather
  than in a deployment;
* **expired evidence is a refusal, not a gap to fill** (`test_expired_evidence_is_a_gap_the_model_can`
  `*_never_cite`, one of the three tests task 4 names);
* every channel says when it is short — and `similar_past` says which of its two silences it is
  (`test_a_history_read_cut_short_says_the_read_stopped_and_not_that_there_is_no_history` is the
  difference between "this pair has never resolved" and "the read could not tell", which is the claim
  `events incident index`/the incident evidence index traded a declared-empty channel for);
* **membership is the incident's own pointer and not a page window** — the four tests at the end of
  `BundleTests`, which is what `correlation`'s grouping made load-bearing: an incident whose members are older
  than the newest 100 events the platform has filed is still bundled in full, and a member of some other
  incident never enters it.
"""
import contextlib
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import rca
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-09T12:00:00Z')
PRODUCER = Actor('bundle-detector', 'producer')
#: A second producer, so one rule on one resource can hold two incidents at once: `state.intake` keys a
#: condition by source *and* rule *and* resource, which is the only clean way to have an open twin of the
#: pair `similar_past` must ignore. Not a convenience — `test_an_incident_that_has_not_resolved_is_not`
#: `*_past` is meaningless without it.
OTHER = Actor('bundle-other-detector', 'producer')
SERVICE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'      # demo-api, declared runs-on probe-1
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'         # probe-1
WINDOW = {'start': '2026-09-09T11:58:00Z', 'end': '2026-09-09T11:59:00Z'}
# A second, wider declaration, used only by the grouped-member test below: `edge-1 --depends-on-->
# api-1 --runs-on--> db-1`. Three resources are the smallest graph in which a grouped member sits
# *further* away than the one hop the topology channel reads, which is the case that proves the signal
# channels follow the members and not only the anchor.
EDGE = 'b4b2b0f1-2f1e-4c3d-9a5a-1f2e3d4c5b6a'
API = '7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d'  # gitleaks:allow
DB = '2c4d6e8f-0a1b-4c2d-9e3f-5a6b7c8d9e0f'


class _EvidenceOnlyStore:
    """A store double that offers `get_evidence` and nothing else.

    This is the structural half of "never from a live query it constructs": if bundle assembly ever
    reaches for a client, a transport, a SQL builder or another read method, it is not on this object.
    """

    def __init__(self, answers: dict[str, dict]) -> None:
        self.answers = answers
        self.asks: list[tuple[str, str]] = []

    def get_evidence(self, source: str, sample_id: str, *, now: dt.datetime | None = None) -> dict:
        self.asks.append((source, sample_id))
        return dict(self.answers.get(sample_id, {'status': 'unavailable'}))


class BundleTests(unittest.TestCase):
    """What goes into a bundle, how wide it is allowed to be, and what it must never contain."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture',
                    now=NOW)

    def file(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def open_incident(self, rule: str = 'api.down', resource: str | None = SERVICE,
                      sample: str | None = 'probe-sample') -> dict:
        """One incident, opened by one intaken event whose evidence row really exists."""
        if sample is not None:
            self.store.put_evidence({'sample_id': sample, 'observed_at': '2026-09-09T11:59:00Z',
                                     'ok': True, 'value': 7}, PRODUCER, now=NOW)
        self.store.intake(event('bundle-detector', resource, rule, 'availability', 'firing',
                                WINDOW, {'sample_id': sample} if sample else {'rule_id': rule},
                                query_type='gatus-result'), PRODUCER, now=NOW)
        return self.store.records('incidents')[0]

    def fired(self, rule: str, resource: str, at: dt.datetime, *, status: str = 'firing',
              producer: Actor = PRODUCER) -> dict:
        """File one verdict on one `(rule, resource)` pair, with no evidence reference to reauthorise.

        The window ends exactly at `at` and `intake` is given the same `at`, so the fixture stays inside
        the clock-skew allowance `validate_event` applies; each call advances that condition's watermark.
        """
        window = {'start': utc_text(at - dt.timedelta(minutes=1)), 'end': utc_text(at)}
        return self.store.intake(event(producer.identity, resource, rule, 'availability', status,
                                      window, {'rule_id': rule}, query_type='gatus-result'),
                                producer, now=at)

    def resolved_pair(self, rule: str, resource: str, *, at: dt.datetime,
                      producer: Actor = PRODUCER) -> str:
        """Open and then resolve an incident on one pair; return the incident id it resolved."""
        opened = self.fired(rule, resource, at, producer=producer)
        self.fired(rule, resource, at + dt.timedelta(minutes=10), status='resolved', producer=producer)
        return opened['incident_id']

    def incident_row(self, incident_id: str) -> dict:
        """One `incidents` row read with raw sqlite, so a channel is compared to the store and not to a guess."""
        with contextlib.closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return dict(next(connection.execute('SELECT * FROM incidents WHERE id=?', (incident_id,))))

    def test_every_channel_is_present_and_names_its_bound(self) -> None:
        body = rca.bundle(self.store, self.open_incident(), self.index, now=NOW)
        self.assertEqual(tuple(body['channels']), rca.CHANNELS)
        for name, channel in body['channels'].items():
            with self.subTest(channel=name):
                self.assertEqual(set(channel), {'items', 'truncated', 'note'})
                self.assertLessEqual(len(channel['items']), rca.MAX_ITEMS[name])
                self.assertIsInstance(channel['truncated'], bool)

    def test_the_member_carries_its_declared_host_and_the_evidence_its_verdict(self) -> None:
        body = rca.bundle(self.store, self.open_incident(), self.index, now=NOW)
        member = body['channels']['members']['items'][0]
        self.assertEqual(member['host_name'], 'probe-1')
        self.assertEqual(member['rule_id'], 'api.down')
        evidence = body['channels']['evidence']['items'][0]
        self.assertEqual(evidence['status'], 'available')
        self.assertEqual(evidence['sample']['value'], 7)
        self.assertEqual(body['gaps'], [])

    def test_expired_evidence_is_a_gap_the_model_can_never_cite(self) -> None:
        """Task 4's second named test: the reference survives, the retained sample does not.

        Two halves, both load-bearing. The gap is *named* (an operator must see that the explanation
        was built on a hole), and the sample bytes are *absent from the bundle text* — the text is what
        a model is given and what `post_validate` checks every claim against, so an expired value
        cannot be cited by anything downstream whether or not it tries.
        """
        self.store.put_evidence({'sample_id': 'long-gone', 'observed_at': '2025-12-01T00:00:00Z',
                                 'ok': True, 'value': 999_999}, PRODUCER, now=NOW)
        self.store.intake(event('bundle-detector', SERVICE, 'api.stale', 'availability', 'firing',
                                WINDOW, {'sample_id': 'long-gone'}, query_type='gatus-result'),
                          PRODUCER, now=NOW)
        body = rca.bundle(self.store, self.store.records('incidents')[0], self.index, now=NOW)
        item = body['channels']['evidence']['items'][0]
        self.assertEqual(item['status'], 'expired')
        self.assertNotIn('sample', item)
        self.assertEqual([gap['status'] for gap in body['gaps']], ['expired'])
        self.assertEqual(body['gaps'][0]['reference'], item['id'])   # the gap names the reference
        self.assertIn(item['id'], body['text'])
        self.assertNotIn('999999', body['text'])
        self.assertNotIn('"value"', body['text'])
        # And the wording of the gap is the honest one: nothing was re-queried to fill it.
        self.assertIn('does not re-query', item['detail'])

    def test_a_reference_that_never_stored_a_sample_is_unavailable_and_says_so(self) -> None:
        body = rca.bundle(self.store, self.open_incident(sample=None), self.index, now=NOW)
        item = body['channels']['evidence']['items'][0]
        self.assertEqual(item['status'], 'unavailable')
        self.assertIn('no stored sample_id', item['detail'])
        self.assertEqual([gap['status'] for gap in body['gaps']], ['unavailable'])

    def test_evidence_is_read_only_through_the_platform_evidence_table(self) -> None:
        """The fake has no `records`, no client and no transport: reaching past `get_evidence` fails here."""
        fake = _EvidenceOnlyStore({'probe-sample': {'status': 'available',
                                                    'sample': {'value': 3},
                                                    'expires_at': '2026-09-24T00:00:00Z'}})
        reference = {'source': 'bundle-detector', 'query_type': 'gatus-result',
                     'parameters': {'sample_id': 'probe-sample'}, 'window': WINDOW,
                     'schema_version': 1, 'expires_at': '2026-09-24T00:00:00Z'}
        channel = rca._evidence(fake, [{'id': 'event-1', 'incident_id': 'incident-1',
                                        'payload': json.dumps({'schema_version': 1, 'window': WINDOW,
                                                               'rule_id': 'r', 'kind': 'availability',
                                                               'status': 'firing', 'observed_at':
                                                               WINDOW['end'],
                                                               'evidence': [reference]})}],
                                'incident-1', now=NOW)
        self.assertEqual(fake.asks, [('bundle-detector', 'probe-sample')])
        self.assertEqual(channel.items[0]['sample'], {'value': 3})

    def test_channels_report_the_bound_that_cut_them_short(self) -> None:
        """A channel that stopped is a channel that says so, and never one that reads as complete.

        Fifteen firings of *one* condition, because one incident is what has members: a later
        evaluation joins the incident the first one opened only when it advances the condition's
        watermark, so the windows below rise, and they stay inside the 60-second clock-skew allowance
        `validate_event` gives `now`.
        """
        self.store.intake(event('bundle-detector', SERVICE, 'api.down', 'availability', 'firing',
                                {'start': '2026-09-09T10:59:00Z', 'end': '2026-09-09T11:58:00Z'},
                                {'rule_id': 'api.down'}, query_type='gatus-result'), PRODUCER, now=NOW)
        incident = self.store.records('incidents')[0]
        for position in range(rca.MAX_ITEMS['members'] + 3):
            second = position + 1
            self.store.intake(event('bundle-detector', SERVICE, 'api.down', 'availability', 'firing',
                                    {'start': '2026-09-09T11:00:00Z',
                                     'end': f'2026-09-09T11:59:{second:02d}Z'},
                                    {'rule_id': 'api.down'}, query_type='gatus-result'),
                              PRODUCER, now=NOW)
        body = rca.bundle(self.store, incident, self.index, now=NOW)
        members_on_file = [row for row in self.store.records('events', rca.RECORDS_LIMIT)
                           if row['incident_id'] == incident['id']]
        self.assertGreater(len(members_on_file), rca.MAX_ITEMS['members'],
                           'the fixture did not outgrow the bound, so the assertion below proves nothing')
        self.assertTrue(body['channels']['members']['truncated'])
        self.assertEqual(len(body['channels']['members']['items']), rca.MAX_ITEMS['members'])

    def test_a_grouped_incident_bundles_every_member_even_after_the_window_moved_on(self) -> None:
        """`correlation`'s group is the unit of analysis, and this read is the only way to see all of it.

        Two conditions, two declared resources, one `runs-on` hop and 30 seconds apart, so the second
        joins the incident the first opened; then the table gets busy. Before the member read was
        re-pointed at `events.incident_id`, this bundle returned whichever members still sat in the
        newest 100 rows and a note admitting the rest might not — which for a group is not a shorter
        answer but a different incident, since the earliest member is exactly what `_span` and
        `earliest-upstream-finding` are decided from.
        """
        admission = self.store.grouping_admission(self.index, PRODUCER, now=NOW)
        opened = self.store.intake(event('bundle-detector', SERVICE, 'api.down', 'availability', 'firing',
                                        WINDOW, {'rule_id': 'api.down'}, query_type='gatus-result'),
                                  PRODUCER, now=NOW, admission=admission)
        joined = self.store.intake(event('bundle-detector', HOST, 'host.down', 'availability', 'firing',
                                        {'start': '2026-09-09T11:58:30Z',
                                         'end': '2026-09-09T11:59:30Z'}, {'rule_id': 'host.down'},
                                        query_type='gatus-result'), PRODUCER, now=NOW, admission=admission)
        self.assertEqual(joined['incident_id'], opened['incident_id'],
                         'the fixture did not group, so nothing below proves the read does')
        with contextlib.closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            incident = dict(next(connection.execute('SELECT id, resource_id FROM incidents WHERE id=?',
                                                    (opened['incident_id'],))))
        inside = rca.bundle(self.store, incident, self.index, now=NOW)
        self.assertIn('host.down', [item['rule_id'] for item in inside['channels']['neighbours']['items']],
                      'a member on a declared neighbour is in `members` and `neighbours` at once, and '
                      'that duplication is kept: `members` says it belongs to this incident, this channel '
                      'is what keeps `earliest-upstream-finding` alive')

        filler = Actor('queue-filler', 'producer')
        for position in range(rca.RECORDS_LIMIT + 20):
            self.store.intake(event('queue-filler', None, f'noise.{position}', 'availability', 'firing',
                                    WINDOW, {'rule_id': f'noise.{position}'}, query_type='gatus-result'),
                              filler, now=NOW)
        window = [row['id'] for row in self.store.records('events', rca.RECORDS_LIMIT)]
        self.assertNotIn(opened['event_id'], window, 'the fixture did not age the anchor out of the page')

        body = rca.bundle(self.store, incident, self.index, now=NOW)
        members = body['channels']['members']['items']
        self.assertEqual(sorted(item['resource_id'] for item in members), sorted([SERVICE, HOST]))
        self.assertEqual(sorted(item['rule_id'] for item in members), ['api.down', 'host.down'])
        self.assertIsNone(body['channels']['members']['note'])
        self.assertFalse(body['channels']['members']['truncated'])
        self.assertEqual(body['resource_id'], SERVICE, 'a group keeps the resource that opened it')
        # The asymmetry this change leaves behind, pinned rather than described: membership is durable and
        # recency is a page, so the same two channels part company once the table gets busy. The rule that
        # reads `neighbours` goes quiet for an old incident while the bundle still knows its members.
        self.assertEqual(body['channels']['neighbours']['items'], [])
        self.assertIn('no firing finding on a declared neighbour',
                      body['channels']['neighbours']['note'])

    def test_similar_past_is_empty_and_says_no_resolved_incident_matches_the_pair(self) -> None:
        """The channel reads history now, so an empty one has to name the search that came back short.

        Up to the incident evidence index this channel was declared empty and its note said so (`this build reads no
        incident history`). That sentence would now be false in the loudest direction — it would tell an
        operator nothing was looked for when something was — so the fixture is the no-match case of a real
        read, and the wording is the search's own. `truncated` stays False: an empty read that finished is
        not a bounded read, and the two must stay distinguishable.
        """
        body = rca.bundle(self.store, self.open_incident(), self.index, now=NOW)
        channel = body['channels']['similar_past']
        self.assertEqual(channel['items'], [])
        self.assertFalse(channel['truncated'])
        self.assertIn('no resolved incident with this rule and resource is on record', channel['note'])

    # --- similar_past: one bounded read of resolved incidents on the same pair -----------------------

    def test_a_resolved_incident_of_the_same_pair_is_the_past_this_channel_shows(self) -> None:
        """Task 3's positive case, with its shape pinned field by field.

        What the channel may say is *this rule on this resource has opened and resolved before, most
        recently at these instants* — so the item carries the pair's own two ids and two instants and the
        event that resolved it, and nothing that could carry a value out of a past incident into a present
        cause claim. The last assertion is the one that keeps `post_validate` unchanged: a sentence built
        from these five fields can only cite text the bundle already holds.
        """
        at = NOW + dt.timedelta(minutes=30)
        past_id = self.resolved_pair('api.down', SERVICE, at=NOW)
        past = self.incident_row(past_id)
        self.assertEqual(past['status'], 'resolved', 'the fixture did not resolve, so nothing below is a test')
        target = self.fired('api.down', SERVICE, at)
        body = rca.bundle(self.store, self.incident_row(target['incident_id']), self.index, now=at)
        channel = body['channels']['similar_past']
        self.assertEqual([item['incident_id'] for item in channel['items']], [past_id])
        item = channel['items'][0]
        self.assertEqual(item['id'], 'similar_past:0')
        self.assertEqual((item['opened_at'], item['resolved_at']), (past['opened_at'], past['updated_at']))
        self.assertEqual(item['resolving_event_id'], past['last_event_id'])
        self.assertEqual(sorted(item), ['id', 'incident_id', 'opened_at', 'resolved_at',
                                       'resolving_event_id'], 'identifiers and instants, never a payload value')
        self.assertNotIn('sample', json.dumps(channel))
        self.assertIsNone(channel['note'], 'a channel that found something invents no note')
        self.assertFalse(channel['truncated'])
        # And the resolution never cites itself: `SIMILAR_SQL` excludes the incident it is explaining, so
        # bundling the past incident returns its own silence rather than its own row.
        self.assertEqual(rca.bundle(self.store, past, self.index, now=at)['channels']['similar_past']
                        ['items'], [])

    def test_a_resolved_incident_of_a_different_pair_is_not_this_incident_s_past(self) -> None:
        """The match is the pair, and both halves of it are doing work.

        Two distractors, one per half: another rule on this resource (a resource-only match would show it)
        and this rule on another resource (a rule-only match would). Both are resolved and both are on
        record, so the empty answer below is the filter and not an empty store.
        """
        other_rule = self.resolved_pair('api.slow', SERVICE, at=NOW)
        other_resource = self.resolved_pair('api.down', HOST, at=NOW)
        for incident_id in (other_rule, other_resource):
            self.assertEqual(self.incident_row(incident_id)['status'], 'resolved')
        target = self.fired('api.down', SERVICE, NOW + dt.timedelta(minutes=30))
        body = rca.bundle(self.store, self.incident_row(target['incident_id']), self.index,
                         now=NOW + dt.timedelta(minutes=30))
        channel = body['channels']['similar_past']
        self.assertEqual(channel['items'], [])
        self.assertFalse(channel['truncated'])
        self.assertIn('no resolved incident with this rule and resource is on record', channel['note'])

    def test_an_incident_that_has_not_resolved_is_not_past(self) -> None:
        """`status='resolved'` is what excludes an open twin, not its position in the row order.

        The open twin is the *newest* incident on the pair, so a read that dropped the status filter would
        put it at the head of the channel and the resolution behind it. `intake` keys a condition by
        producer as well as rule and resource, which is how one pair legitimately holds two incidents here.
        """
        past_id = self.resolved_pair('api.down', SERVICE, at=NOW)
        target = self.fired('api.down', SERVICE, NOW + dt.timedelta(minutes=30))
        twin = self.fired('api.down', SERVICE, NOW + dt.timedelta(minutes=40), producer=OTHER)
        self.assertNotEqual(twin['incident_id'], target['incident_id'],
                           'the fixture did not open a second incident on the pair')
        self.assertEqual(self.incident_row(twin['incident_id'])['status'], 'open')
        body = rca.bundle(self.store, self.incident_row(target['incident_id']), self.index,
                         now=NOW + dt.timedelta(minutes=45))
        self.assertEqual([item['incident_id'] for item in body['channels']['similar_past']['items']],
                        [past_id], 'the open twin is not history, newest first or otherwise')

    def test_a_history_read_cut_short_says_the_read_stopped_and_not_that_there_is_no_history(self) -> None:
        """The instruction budget is honesty machinery here too, and it is a separate budget.

        Driven to nothing the read is interrupted before it can finish, and the only acceptable answer is
        "more may exist" — a `similar_past` that reads "nothing has resolved on this pair" would let a
        rule, and then a model, treat an unreadable history as a quiet one. The member assertion is the
        other half: the two reads must not share one ceiling, or cutting off the history read would
        silently empty the incident's own members too.
        """
        self.resolved_pair('api.down', SERVICE, at=NOW)
        target = self.fired('api.down', SERVICE, NOW + dt.timedelta(minutes=30))
        row = self.incident_row(target['incident_id'])
        with mock.patch.object(rca, 'SIMILAR_READ_INSTRUCTIONS', 1):
            body = rca.bundle(self.store, row, self.index, now=NOW + dt.timedelta(minutes=30))
        channel = body['channels']['similar_past']
        self.assertEqual(channel['items'], [])
        self.assertTrue(channel['truncated'])
        self.assertIn('instruction budget', channel['note'])
        self.assertIn('more resolved incidents of this pair may exist', channel['note'])
        self.assertNotIn('no resolved incident', channel['note'])
        self.assertTrue(body['channels']['members']['items'],
                       'the member read kept its own bound and still returned this incident\'s event')

    def test_more_resolved_incidents_than_the_channel_holds_are_reported_as_short(self) -> None:
        """The row bound, kept honest by the one extra row the read asks for.

        Seven resolved incidents, five shown, `truncated` true: `MAX_ITEMS` alone could not tell a full
        channel from a short one, which is why `SIMILAR_SQL` asks for `MAX_ITEMS + 1` and lets `_channel`
        see the row it must drop.
        """
        ids = [self.resolved_pair('api.down', SERVICE, at=NOW + dt.timedelta(minutes=position * 15))
              for position in range(rca.MAX_ITEMS['similar_past'] + 2)]
        at = NOW + dt.timedelta(minutes=200)
        target = self.fired('api.down', SERVICE, at)
        body = rca.bundle(self.store, self.incident_row(target['incident_id']), self.index, now=at)
        channel = body['channels']['similar_past']
        self.assertEqual(len(channel['items']), rca.MAX_ITEMS['similar_past'])
        self.assertTrue(channel['truncated'])
        self.assertEqual([item['incident_id'] for item in channel['items']], list(reversed(ids[-5:])),
                        'newest filed first, and the five newest are the ones shown')

    def test_an_absent_index_is_reported_as_unavailable_and_never_as_an_empty_graph(self) -> None:
        """`nothing declared` and `the index could not be read` are different facts about the world."""
        incident = self.open_incident()
        without = rca.bundle(self.store, incident, None, now=NOW)
        self.assertIn('index not configured', without['channels']['topology']['note'])
        self.assertIsNone(without['channels']['declaration']['note'])
        self.assertEqual(without['channels']['declaration']['items'][0]['host_name'], 'Not declared')
        broken = rca.bundle(self.store, incident, self.root / 'absent' / 'index.db', now=NOW)
        self.assertIn('unreadable', broken['channels']['topology']['note'])
        self.assertEqual(broken['channels']['declaration']['items'][0]['resource_name'],
                         'Inventory unavailable')

    def test_the_declared_graph_is_one_hop_and_labelled_by_direction(self) -> None:
        body = rca.bundle(self.store, self.open_incident(resource=HOST), self.index, now=NOW)
        nodes = body['channels']['topology']['items']
        self.assertEqual([(node['name'], node['direction']) for node in nodes],
                         [('demo-api', 'downstream')])
        self.assertEqual(body['channels']['declaration']['items'][0]['resource_name'], 'probe-1')

    def test_the_bundle_digest_and_bytes_are_of_the_text_a_model_is_given(self) -> None:
        body = rca.bundle(self.store, self.open_incident(), self.index, now=NOW)
        self.assertEqual(body['bytes'], len(body['text'].encode()))
        self.assertEqual(len(body['digest']), 64)
        self.assertNotIn('digest', body['text'])

    def test_the_bundle_reads_no_telemetry_and_imports_no_optional_package(self) -> None:
        """Design 3 as a grep, stated exactly as far as it reaches.

        What must be true: this module writes no statement of its own against the telemetry store, no
        DDL, no INSERT/UPDATE/DELETE anywhere (its only write is `Store.audit`), and imports neither the
        store backends nor the optional `ai` package. What is *also* true and therefore named rather
        than hidden: it holds five SQL literals, every one of them a fixed read of the platform's own
        SQLite file — the explanation row (`READ_SQL`), the same row for a page (`latest_many`), the
        incident's member events (`MEMBER_SQL`, correlation's membership pointer) and the resolved incidents of
        one pair (`SIMILAR_SQL`, `similar_past`, events incident index). Counting them is what makes "no branch issues a
        query" checkable instead of a memory, so a sixth statement is a new table or a new read path and
        has to be justified here before it is written.

        The `ai` half is what keeps `tests/test_ai_component.py`'s empty `ALLOWED_IMPORTERS` true: the
        seam is a callable a caller hands in, so a deployment without generation has no optional
        dependency missing rather than a runtime branch to get wrong.
        """
        path = ROOT / 'local_observe' / 'platform' / 'rca.py'
        text = path.read_text(encoding='utf-8')
        lowered = text.lower()
        imports = '\n'.join(line for line in text.splitlines()
                            if line.strip().startswith(('import ', 'from ')))
        for forbidden in ('local_observe.ai', 'local_observe.store', 'clickhouse', 'local_observe.http',
                          'insert ', 'update ', 'delete ', 'drop ', 'alter ', 'executescript'):
            with self.subTest(marker=forbidden):
                self.assertNotIn(forbidden, imports if forbidden.startswith('local_observe') else lowered)
        # Five SELECTs and no write: the per-incident explanation read (`READ_SQL`, one bound id), the
        # page read (`latest_many`, a bound operation word plus a bound id list), the member read
        # (`MEMBER_SQL`, a bound id plus a bound row ceiling) and the incident-history read
        # (`SIMILAR_SQL`, four bounds). A third statement was the count until the member read replaced the
        # newest-100 page window and a fourth until `similar_past` stopped being declared empty: both
        # changes are the subject of the tests below, and this number is where they have to be admitted
        # rather than argued around.
        self.assertEqual(lowered.count('select '), 5, 'a further statement text appeared')
        single = text[text.index('READ_SQL'):text.index('READ_SQL') + 260]
        self.assertIn('FROM audit', single)
        self.assertEqual(single.count('?'), 1, 'the one-incident read takes one bound parameter and no text')
        members = text[text.index('MEMBER_SQL'):text.index('MEMBER_SQL') + 200]
        self.assertIn('FROM events WHERE incident_id=?', members,
                      'the member read is keyed by the incident and by nothing an operator can type')
        self.assertEqual(members.count('?'), 2, 'one bound id and one bound row ceiling, and nothing else')
        self.assertNotIn('join', members.lower(), 'the member read reaches one table')
        # The history read is anchored on the incident tables, not on `events` alone: its FROM is
        # `incidents`, its one join is the resolving event, and every value it filters on arrives bound —
        # the incident being explained, its resource, its rule and its row ceiling. An unbounded fourth
        # placeholder would mean a predicate built from text, which is what this test exists to catch.
        history = text[text.index('SIMILAR_SQL = ('):text.index('SIMILAR_SQL = (') + 520]
        self.assertIn('FROM incidents i', history, 'the past is read off incidents, not off events')
        self.assertIn('JOIN events e ON e.id=i.last_event_id', history,
                      'the one join is the event that resolved the incident, by id and by nothing else')
        self.assertEqual(history.count('?'), 4,
                        'own incident, resource, rule and row ceiling, all four bound')
        self.assertIn("i.status='resolved'", history, 'only a resolved incident is past')
        self.assertIn('ORDER BY i.rowid DESC', history, 'newest filed first, stated and not assumed')
        page = text[text.index('def latest_many'):text.index('def latest_many') + 2_000]
        for write in ('insert', 'update ', 'delete', 'drop', 'alter'):
            with self.subTest(page_marker=write):
                self.assertNotIn(write, page.lower().replace('updated', ''))
        self.assertIn('operation=?', page,
                      'the page read binds its operation word rather than pasting it in')
        self.assertIn('?', page)

    # --- the member read: correlation's pointer, not a page window -----------------------------------------

    def test_an_incident_older_than_the_newest_100_events_is_still_fully_bundled(self) -> None:
        """The one defect this read exists to keep shut: an incident that aged out of a page window.

        Two halves, both asserted. *Before* the bundle: the incident's own event is genuinely no longer
        inside `Store.records('events', 100)`, so the fixture proves the case and does not merely name
        it. *After*: the member channel carries it, its evidence is reauthorised, the span is the
        incident's own and not empty, the channel is not `truncated` and carries no note — and `capped`
        still says the recency window came back full, because that is a separate fact about three other
        channels and this bundle must not hide it to look healthy.
        """
        incident = self.open_incident()
        member_id = incident['last_event_id']
        noise = Actor('queue-filler', 'producer')
        for position in range(rca.RECORDS_LIMIT + 20):
            self.store.intake(event('queue-filler', None, f'noise.{position}', 'availability', 'firing',
                                    WINDOW, {'rule_id': f'noise.{position}'}, query_type='gatus-result'),
                              noise, now=NOW)
        window = [row['id'] for row in self.store.records('events', rca.RECORDS_LIMIT)]
        self.assertGreaterEqual(len(window), rca.RECORDS_LIMIT)
        self.assertNotIn(member_id, window, 'the fixture did not push the member out of the window')

        body = rca.bundle(self.store, incident, self.index, now=NOW)
        items = body['channels']['members']['items']
        self.assertEqual([item['event_id'] for item in items], [member_id])
        self.assertEqual(items[0]['host_name'], 'probe-1')
        self.assertIsNone(body['channels']['members']['note'],
                          'a complete read has no gap to name, whatever the page window did')
        self.assertFalse(body['channels']['members']['truncated'])
        self.assertEqual(body['span'], {'first': utc_text(timestamp(WINDOW['end'])),
                                       'last': utc_text(timestamp(WINDOW['end']))},
                         'an aged-out incident still dates its own span off its own member')
        self.assertEqual([item['status'] for item in body['channels']['evidence']['items']],
                         ['available'], 'an aged-out incident is not an incident without evidence')
        self.assertTrue(body['capped'], 'the recency channels are still bounded by the page they read')

    def test_a_member_of_another_incident_never_enters_this_bundle(self) -> None:
        """Membership is the incident's own pointer and not "whatever the store had lately".

        Both incidents are on declared resources, so the other one's finding is exactly the kind of row
        a wider read could have swept in — and `neighbours` is the only channel allowed to speak about a
        resource this incident does not own.
        """
        mine = self.open_incident(rule='api.down', resource=SERVICE, sample=None)
        theirs = self.store.intake(event('bundle-detector', HOST, 'host.down', 'availability', 'firing',
                                         WINDOW, {'rule_id': 'host.down'}, query_type='gatus-result'),
                                   PRODUCER, now=NOW)
        body = rca.bundle(self.store, mine, self.index, now=NOW)
        member_ids = [item['event_id'] for item in body['channels']['members']['items']]
        self.assertEqual(member_ids, [mine['last_event_id']])
        self.assertNotIn(theirs['event_id'], member_ids)
        self.assertEqual(body['channels']['members']['note'], None)
        self.assertEqual([item['resource_id'] for item in body['channels']['members']['items']],
                         [SERVICE])

    def test_a_member_read_cut_short_says_the_read_failed_and_not_that_members_are_absent(self) -> None:
        """The instruction budget is honesty machinery, not a performance knob.

        With the bound driven to nothing the scan is interrupted before it can finish, and the only
        acceptable answer is "membership is unknown": an empty member channel that reads as a memberless
        incident would make `_span` empty, and every lookback and "did the change come first" test
        downstream would quietly stop having an incident to date from.
        """
        incident = self.open_incident()
        with mock.patch.object(rca, 'MEMBER_READ_INSTRUCTIONS', 1):
            body = rca.bundle(self.store, incident, self.index, now=NOW)
        channel = body['channels']['members']
        self.assertEqual(channel['items'], [])
        self.assertTrue(channel['truncated'])
        self.assertIn('instruction budget', channel['note'])
        self.assertIn('may have members this bundle does not show', channel['note'])
        self.assertEqual(body['span'], {'first': '', 'last': ''},
                         'an unreadable membership is never answered with a guessed span')

    def test_a_member_row_that_cannot_be_read_is_named_as_unreadable(self) -> None:
        """Rows on record that this build cannot parse are a third silence, and get their own sentence.

        "Nothing was filed", "the read did not finish" and "the platform holds bytes we cannot read" are
        three facts an operator acts on differently; collapsing the last into the first is how a damaged
        store comes back looking like a quiet night.
        """
        incident = self.open_incident()
        with contextlib.closing(sqlite3.connect(self.store.path)) as connection:
            connection.execute("UPDATE events SET payload='{not json' WHERE id=?",
                               (incident['last_event_id'],))
            connection.commit()
        body = rca.bundle(self.store, incident, self.index, now=NOW)
        channel = body['channels']['members']
        self.assertEqual(channel['items'], [])
        self.assertTrue(channel['truncated'])
        self.assertIn('none of them is a payload this build can read', channel['note'])

    # --- correlation's group is the unit of analysis ---------------------------------------------------

    def chain(self) -> Path:
        """Build the three-resource declaration named at the top of this file.

        `index.build` is the only author of an inventory file, so this fixture goes through the product's
        own validator rather than hand-laid SQL: a declared document the builder refuses is a fixture bug
        and fails here, not somewhere downstream where it would look like a bundle defect.
        """
        path = self.root / 'chain.db'
        index.build({'schema_version': 1, 'resources': [
            {'id': EDGE, 'kind': 'service', 'name': 'edge-1', 'aliases': [], 'attributes': {},
             'relations': [{'type': 'depends-on', 'target': API}]},
            {'id': API, 'kind': 'service', 'name': 'api-1', 'aliases': [], 'attributes': {},
             'relations': [{'type': 'runs-on', 'target': DB}]},
            {'id': DB, 'kind': 'host', 'name': 'db-1', 'aliases': [], 'attributes': {},
             'relations': []}]}, path, 'fixture', now=NOW)
        return path

    def grouped(self, chain: Path) -> dict:
        """Open two conditions two declared hops apart and let `correlation` join them; return the incident.

        The grouping is asserted and not assumed: if the admission ever stops linking, the test below
        would be describing two unrelated incidents, so this fails right here instead.
        """
        admission = self.store.grouping_admission(chain, PRODUCER, now=NOW)
        anchor = self.store.intake(event('bundle-detector', EDGE, 'edge.down', 'availability', 'firing',
                                        WINDOW, {'rule_id': 'edge.down'}, query_type='gatus-result'),
                                  PRODUCER, now=NOW, admission=admission)
        joined = self.store.intake(event('bundle-detector', DB, 'db.down', 'availability', 'firing',
                                        WINDOW, {'rule_id': 'db.down'}, query_type='gatus-result'),
                                  PRODUCER, now=NOW, admission=admission)
        self.assertEqual(joined['incident_id'], anchor['incident_id'],
                         'the fixture did not group, so nothing below can prove the read does')
        return next(row for row in self.store.records('incidents')
                    if row['id'] == anchor['incident_id'])

    def test_a_drift_verdict_on_a_grouped_member_reaches_the_signal_channel(self) -> None:
        """`changes` follows the members, not only the anchor's one declared hop.

        `db-1` sits two hops above `edge-1`, so the topology channel — one hop, by design, and asserted
        still one hop here — cannot name it. Before the member re-point a drift report about a resource
        this incident already holds as a member was filtered out as unrelated; `correlation` decided it is the
        same event, and `change-before-finding` is the rule that had no way to say so.
        """
        chain = self.chain()
        incident = self.grouped(chain)
        self.store.intake(event('bundle-detector', DB, 'config.drift', 'drift', 'firing', WINDOW,
                               {'rule_id': 'config.drift'}, query_type='observed-snapshot'),
                          PRODUCER, now=NOW)
        body = rca.bundle(self.store, incident, chain, now=NOW)
        self.assertNotIn(DB, [item['resource_id'] for item in body['channels']['topology']['items']],
                         'the graph channel is one hop and stays one hop')
        self.assertEqual([item['resource_id'] for item in body['channels']['changes']['items']], [DB])
        self.assertEqual([item['id'] for item in body['channels']['changes']['items']], ['changes:0'],
                         'citation ids are assigned after the sort, so a stored citation stays true')
        self.assertIn('change-before-finding', [item.rule for item in rca.candidates(body)],
                      'the change is on record and the floor is now able to name it')


class ExplanationRecordTests(unittest.TestCase):
    """The one durable artefact this component writes, and the four rules that bound it."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture',
                    now=NOW)
        producer = Actor('bundle-producer', 'producer')
        self.store.put_evidence({'sample_id': 'bundle-sample', 'observed_at': '2026-09-09T11:59:00Z',
                                 'ok': False, 'value': 21.5}, producer, now=NOW)
        self.store.intake(event('bundle-producer', SERVICE, 'api.down', 'availability', 'firing',
                                WINDOW, {'sample_id': 'bundle-sample'}, query_type='gatus-result'),
                          producer, now=NOW)
        self.incident = self.store.records('incidents')[0]

    def body(self, **kwargs) -> dict:
        return rca.bundle(self.store, self.incident, self.index, now=NOW, **kwargs)

    def test_the_record_fields_are_a_fixed_set_that_carries_no_prose(self) -> None:
        """`EXPLANATION_KEYS` is the contract; this test is the reason it is that size."""
        body = self.body()
        detail = rca.explanation_record('rca-bundle', body, rca.explain(body))
        self.assertEqual(set(detail), set(rca.EXPLANATION_KEYS))
        self.assertEqual(detail['schema_version'], rca.EXPLANATION_SCHEMA_VERSION)
        self.assertEqual(detail['producer'], 'rca-bundle')
        self.assertNotIn('explanation', detail, 'model prose has no field here, so it cannot be stored')
        self.assertNotIn('text', detail)
        self.assertNotIn('bundle_text', detail)

    def test_no_telemetry_sample_value_reaches_the_durable_record(self) -> None:
        """The record cites the evidence row and never copies it.

        The fixture's value is `21.5` and it is in the bundle the model would be shown; it must not be
        in the record, because a control-plane row that outlives the retention window while quoting a
        sample inside it is the erasure of a retention limit and not an annotation (`query adapter`).
        """
        body = self.body()
        self.assertIn('21.5', body['text'], 'the fixture must actually have stored a value')
        detail = rca.explanation_record('rca-bundle', body, rca.explain(body))
        self.assertNotIn('21.5', json.dumps(detail))

    def test_a_gap_only_explanation_says_the_only_honest_word(self) -> None:
        """`confidence` cannot be empty, absent or a string the reader has to interpret.

        Its incident cites a `sample_id` that was never stored, which is the case this component exists
        to refuse politely: there is nothing to read, so the answer is `unknown` plus a counted gap, and
        not the fluency of an empty candidate list.
        """
        producer = Actor('bundle-producer', 'producer')
        # A resource the declared inventory has never heard of: no neighbours, so no rule may borrow the
        # other incident in this fixture as its upstream cause.
        blind_resource = '9a7d1f2c-3b4e-4a5d-9c6b-1e2f3a4b5c6d'
        self.store.intake(event('bundle-producer', blind_resource, 'host.blind', 'availability',
                                'firing', WINDOW, {'sample_id': 'never-stored'},
                                query_type='gatus-result'), producer, now=NOW)
        blind = next(row for row in self.store.records('incidents')
                     if row['resource_id'] == blind_resource)
        body = rca.bundle(self.store, blind, self.index, now=NOW)
        outcome = rca.explain(body)
        self.assertEqual(outcome['confidence'], 'unknown')
        self.assertEqual(outcome['candidates'], [])
        detail = rca.explanation_record('rca-bundle', body, outcome)
        self.assertEqual(detail['confidence'], 'unknown')
        self.assertGreater(detail['gaps'], 0, 'a refusal with no gap counted is a shrug')
        self.assertEqual(detail['citations'], [], 'a gap is not a citation')
        for candidate in outcome['candidates']:
            self.assertIn(candidate.citations[0], body['citeable'],
                          'a candidate may not cite a row the bundle declared unavailable')

    def test_a_record_written_by_an_unknown_schema_is_refused_rather_than_guessed_at(self) -> None:
        """Newer shapes still read; a version this reader cannot place does not render at all.

        The floor and not the ceiling is the deliberate half: refusing a record because the *viewer* is
        old would delete an explanation that is still true of the incident it describes.
        """
        self.assertTrue(rca.readable_schema({'schema_version': 1}))
        self.assertTrue(rca.readable_schema({'schema_version': 2}),
                        'a future field this build does not read is not a reason to hide the row')
        for bad in ({}, {'schema_version': 0}, {'schema_version': '1'}, {'schema_version': True},
                    {'schema_version': None}, {'schema_version': 1.0}):
            with self.subTest(record=bad):
                self.assertFalse(rca.readable_schema(bad))

    def test_the_round_records_once_and_a_second_round_records_nothing(self) -> None:
        first = rca.tick(self.store, self.index, config={}, source='rca-bundle', now=NOW)
        self.assertEqual(first['written'], 1)
        second = rca.tick(self.store, self.index, config={}, source='rca-bundle',
                          now=NOW + dt.timedelta(minutes=5))
        self.assertEqual(second['unchanged'], 1)
        with contextlib.closing(sqlite3.connect(self.store.path)) as connection:
            rows = connection.execute("SELECT count(*) FROM audit WHERE operation='rca.explained'"
                                      ).fetchone()[0]
        self.assertEqual(rows, 1)
        stored = rca.read_latest(self.store, self.incident['id'])
        self.assertEqual(stored['confidence'], 'unknown')
        self.assertEqual(stored['rules'], [])
        self.assertFalse(stored['llm_used'])
        self.assertEqual(stored['degraded_reason'], 'no_rule_floor')
        self.assertEqual(len(stored['bundle_digest']), 64)


if __name__ == '__main__':
    unittest.main()
