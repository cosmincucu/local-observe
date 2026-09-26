"""detection content: the re-derived detection content, executed against the SQL it compiles to.

Three claims are checked here, and the first is the reason the file exists.

**A compiled rule is only worth its rows.** `docs/COMPONENTS.md` §5 asks the security-detection
scenario for positive *and* negative reference-schema fixtures, an absent sensor that is detected, and
a replay that does not multiply findings; integration validation adds supported field and time semantics, duplicate
handling and bounded queries. The fixtures under `examples/sigma/fixtures/` are log rows in the shape
the store holds (`body` plus the two `attributes_string` keys the reference mapping reads), and this
file runs each rule's committed compiled SQL against them.

**What executes the SQL is a reader of it, not a copy of it.** No ClickHouse is reachable from the unit
tier, so the fake client parses the predicate *the pinned compiler emitted* — `countIf(coalesce((<p>),
false))` — and evaluates that text over the fixture rows. It understands exactly the shapes this backend
produces for the validated modifiers (`ILIKE` terms with `%`/`_` wildcards and backslash escapes,
AND/OR/NOT composition) and **raises** on anything else, so a backend that starts emitting SQL this
reader cannot interpret fails the tier instead of quietly reporting zero. Two things therefore stay open
and are recorded in `components/control/sigma/conformance.md` rather than implied here: this proves the
predicate means what the YAML says; it does not prove the server's own LIKE, time-zone or aggregation
behaviour, which the 2026-09-06 staging run did against a real ClickHouse.

**Where a maintenance window belongs.** `examples/sigma/privileged-shell-spawn.yaml` ports a rule whose
v0.1 form rendered a time band into its own SQL. Here the band is `suppression.py`'s, so
`MaintenanceWindowTests` files a Sigma finding beside a declared window over its rule id and asserts
both halves: the send is refused and named, and the finding is not forgotten. It also asserts the
window does **not** cover the rule's coverage event — a licence to be quiet during planned work is not
a licence to hide that the producer went silent.
"""
import datetime as dt
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from typing import Any, NamedTuple

from local_observe.http import TransportError
from local_observe.inventory.index import build
from local_observe.inventory.validation import digest, read_document, timestamp, utc_text
from local_observe.platform import suppression
from local_observe.platform.sigma_runner import artifact, measurement_report, measurement_status, tick
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'examples' / 'sigma' / 'fixtures'
COMPILED = ROOT / 'examples' / 'sigma' / 'compiled'
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
HUMAN = Actor('window-operator', 'human')
PRODUCER = Actor('sigma-stage', 'producer')
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)

#: The scoping clauses every compiled statement carries, quoted literally. The fake client applies them
#: itself, so these pins are what stop the fake from becoming a second, laxer authority over scope: a
#: compiler change to the window or the filters has to move these strings in the same commit.
WHERE_WINDOW = 'WHERE timestamp >= {start_ns:UInt64} AND timestamp < {end_ns:UInt64}'
WHERE_SCOPE = ("AND resources_string['resource_id'] = {resource_id:String}",
               "AND attributes_string['event.dataset'] = {dataset:String}")
#: Sigma field name -> the attribute the reference mapping reads (`None` for the log line itself), and
#: the projection the compiler emits for it. `CompilerReaderTests` asserts the projection text against
#: every shipped artifact, so a field added to the compiler must be added here with its real projection
#: or this reader stops reading the thing it claims to read.
SOURCE_OF = {'Image': 'process.executable', 'CommandLine': 'process.command_line', 'Body': None}
PROJECTIONS = {
    'Image': "if(mapContains(attributes_string, 'process.executable'), "
             "attributes_string['process.executable'], NULL) AS Image",
    'CommandLine': "if(mapContains(attributes_string, 'process.command_line'), "
                   "attributes_string['process.command_line'], NULL) AS CommandLine",
    'Body': 'body AS Body',
}
IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z_0-9]*')
MATCH_PREDICATE = re.compile(r'countIf\(coalesce\((.*), false\)\) AS match_count', re.DOTALL)


def tokens(text: str) -> list[Any]:
    """Split a compiled predicate into parentheses, words and quoted LIKE patterns.

    An unterminated pattern is refused: a half-read pattern would match *more* than the rule says,
    which is the wrong direction to be wrong in for a security rule.
    """
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
        elif char in '()':
            out.append(char)
            index += 1
        elif char == "'":
            end = index + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                    continue
                if text[end] == "'":
                    break
                end += 1
            if end >= len(text):
                raise ValueError('Unterminated LIKE pattern in compiled SQL')
            out.append(('pattern', text[index + 1:end]))
            index = end + 1
        else:
            found = IDENTIFIER.match(text, index)
            if not found:
                raise ValueError('Unsupported token in compiled predicate: ' + text[index:index + 24])
            out.append(found.group(0))
            index = found.end()
    return out


class Reader:
    """A closed parser for the predicate shapes this pinned backend emits, and nothing else.

    Grammar — anything outside it raises: `expression := term (OR term)*`, `term := factor (AND
    factor)*`, `factor := NOT factor | '(' expression ')' | FIELD 'ILIKE' pattern`. A field outside the
    artifact's `required_fields`, or a comparison other than `ILIKE`, is a refusal.
    """

    def __init__(self, text: str, fields: list[str]):
        self.items, self.position, self.fields = tokens(text), 0, set(fields)

    def parse(self) -> Any:
        node = self.or_expression()
        if self.position != len(self.items):
            raise ValueError('Trailing tokens in compiled predicate')
        return node

    def or_expression(self) -> Any:
        parts = [self.and_expression()]
        while self.peek() == 'OR':
            self.take()
            parts.append(self.and_expression())
        return parts[0] if len(parts) == 1 else ('or', parts)

    def and_expression(self) -> Any:
        parts = [self.factor()]
        while self.peek() == 'AND':
            self.take()
            parts.append(self.factor())
        return parts[0] if len(parts) == 1 else ('and', parts)

    def factor(self) -> Any:
        if self.peek() == 'NOT':
            self.take()
            return ('not', self.factor())
        if self.peek() == '(':
            self.take()
            node = self.or_expression()
            if self.peek() != ')':
                raise ValueError('Unbalanced parenthesis in compiled predicate')
            self.take()
            return node
        return self.term()

    def term(self) -> Any:
        field = self.take()
        if not isinstance(field, str) or field not in self.fields:
            raise ValueError('Predicate names a field outside the artifact: ' + str(field))
        if self.take() != 'ILIKE':
            raise ValueError('Only the validated ILIKE comparison is readable here')
        pattern = self.take()
        if not (isinstance(pattern, tuple) and pattern[0] == 'pattern'):
            raise ValueError('ILIKE needs a quoted pattern')
        return ('like', field, pattern[1])

    def peek(self) -> Any:
        return self.items[self.position] if self.position < len(self.items) else None

    def take(self) -> Any:
        item = self.peek()
        if item is None:
            raise ValueError('Compiled predicate ended early')
        self.position += 1
        return item


def predicate_source(sql: str) -> str:
    """The `match_count` predicate text inside a compiled statement, ready to hand to `Reader`."""
    found = MATCH_PREDICATE.search(sql)
    if not found:
        raise ValueError('Compiled SQL has no bounded match_count predicate')
    return found.group(1)


def match_pattern(value: str, pattern: str) -> bool:
    """ClickHouse `ILIKE` semantics for the patterns this compiler can produce: `%`, `_`, backslash.

    An escape other than `\\%`, `\\_` or `\\\\` is refused rather than guessed at — the source estate's
    own tuning history is a story about a matcher that silently meant something else.
    """
    parts, index = [], 0
    while index < len(pattern):
        char = pattern[index]
        if char == '\\':
            following = pattern[index + 1:index + 2]
            if following not in ('%', '_', '\\'):
                raise ValueError('Unsupported LIKE escape')
            parts.append(re.escape(following))
            index += 2
            continue
        parts.append('.*' if char == '%' else '.' if char == '_' else re.escape(char))
        index += 1
    return re.match('^' + ''.join(parts) + '$', value, re.IGNORECASE | re.DOTALL) is not None


def evaluate(node: Any, values: dict[str, Any]) -> bool:
    """Apply one parsed predicate to one row. A NULL field makes its term false, never unknown.

    The backend wraps the predicate in `coalesce((...), false)` and every term it emits for the
    validated modifiers is a positive `ILIKE`, possibly under `NOT`. For that shape ClickHouse's
    three-valued logic and this two-valued reader agree: a NULL operand makes the composition NULL, and
    `coalesce` answers that as false — the same answer returned here. `Reader` refuses every other
    shape, so the agreement cannot drift outside the shapes it was argued for.
    """
    kind = node[0]
    if kind == 'or':
        return any(evaluate(child, values) for child in node[1])
    if kind == 'and':
        return all(evaluate(child, values) for child in node[1])
    if kind == 'not':
        return not evaluate(node[1], values)
    _, field, pattern = node
    value = values.get(field)
    return isinstance(value, str) and match_pattern(value, pattern)


def row_values(compiled: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """One fixture row as the mapping sees it: the mapped attribute, or None when it is absent."""
    return {field: (row['body'] if SOURCE_OF[field] is None else row['attributes_string'].get(SOURCE_OF[field]))
            for field in compiled['required_fields']}


def counts(compiled: dict[str, Any], rows: list[dict[str, Any]], parameters: dict[str, Any]) -> dict[str, int]:
    """The three aggregates the compiled statement asks for, read off the fixture rows."""
    kept = [row for row in rows
            if parameters['start_ns'] <= row['timestamp_ns'] < parameters['end_ns']
            and row['resources_string'].get('resource_id') == parameters['resource_id']
            and row['attributes_string'].get('event.dataset') == parameters['dataset']]
    fields = compiled['required_fields']
    node = Reader(predicate_source(compiled['sql']), fields).parse()
    values = [row_values(compiled, row) for row in kept]
    return {'source_count': len(kept),
            'usable_count': sum(1 for one in values if all(one[field] is not None for field in fields)),
            'match_count': sum(1 for one in values if evaluate(node, one))}


def shift(case: dict[str, Any], windows: int) -> list[dict[str, Any]]:
    """A fixture's rows moved `windows` evaluation windows later, for multi-window runs."""
    offset = windows * case['window_seconds'] * 10**9
    return [dict(row, timestamp_ns=row['timestamp_ns'] + offset) for row in case['rows']]


def window_parameters(case: dict[str, Any], dataset: str, *, windows: int = 0) -> dict[str, Any]:
    """The bound parameters `tick()` sends for one fixture's evaluation instant."""
    instant = timestamp(case['evaluate_at']) + dt.timedelta(seconds=windows * case['window_seconds'])
    end = dt.datetime.fromtimestamp(int(instant.timestamp()) // case['window_seconds'] * case['window_seconds'],
                                    dt.timezone.utc)
    start = end - dt.timedelta(seconds=case['window_seconds'])

    def nanos(moment: dt.datetime) -> int:
        return int((moment - EPOCH).total_seconds()) * 10**9

    return {'start_ns': nanos(start), 'end_ns': nanos(end), 'resource_id': RESOURCE, 'dataset': dataset}


def fixtures(rule: str) -> list[dict[str, Any]]:
    """Every committed fixture for one rule, ordered by file name so a failure names the case."""
    return [json.loads(path.read_text(encoding='utf-8')) for path in sorted((FIXTURES / rule).glob('*.json'))]


class FixtureQuery:
    """The store's stand-in: it answers a compiled rule from committed rows, never from a guess."""

    def __init__(self, compiled: dict[str, Any], rows: list[dict[str, Any]]):
        self.compiled, self.rows, self.calls, self.seen = compiled, rows, 0, []

    def query(self, sql: str, parameters: dict[str, Any]) -> dict[str, int]:
        self.calls += 1
        self.seen.append(parameters)
        if sql != self.compiled['sql']:
            raise AssertionError('The runner asked something other than the reviewed artifact')
        return counts(self.compiled, self.rows, parameters)


class Recorder:
    """The platform's stand-in: captures the canonical batch instead of posting it."""

    def __init__(self) -> None:
        self.batches: list[dict[str, Any]] = []

    def request(self, method: str, path: str, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.batches.append({'path': path, 'payload': payload})
        return 200, {'status': 'accepted'}

    def events(self) -> dict[str, dict[str, Any]]:
        return {item['payload']['rule_id']: item['payload']
                for item in self.batches if item['path'] == '/v1/events'}


class Intake:
    """A real platform intake over `Store`, so identity and incident behaviour stay the product's own."""

    def __init__(self, store: Store, now: dt.datetime, *, lose_acknowledgement: bool = False) -> None:
        self.store, self.now, self.lose = store, now, lose_acknowledgement

    def request(self, method: str, path: str, payload: dict[str, Any]) -> tuple[int, Any]:
        actor = Actor('sigma-stage', 'producer')
        if path != '/v1/events':
            return 200, self.store.put_evidence(payload, actor, now=self.now)
        if self.lose:
            self.lose = False
            raise TransportError('Lost acknowledgement')
        return 200, self.store.intake(payload, actor, now=self.now)


class Run(NamedTuple):
    """One fixture driven through `tick()`, with everything a test then wants to read."""

    result: str
    query: FixtureQuery
    platform: Any
    compiled: dict[str, Any]
    now: dt.datetime


class Harness(unittest.TestCase):
    """One scratch index, platform and cursor, plus the single way a fixture is driven."""

    def setUp(self) -> None:
        """Fresh scratch files per test: a cursor that survived another test is not evidence."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'index.db'
        build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture')
        self.store = Store(self.root / 'state.db')
        self.cursor = self.root / 'cursor.json'

    def case(self, rule: str, name: str) -> dict[str, Any]:
        return json.loads((FIXTURES / rule / (name + '.json')).read_text(encoding='utf-8'))

    def drive(self, rule: str, name: str, *, windows: int = 0, capture: bool = False) -> Run:
        """Run one window of one fixture. `capture` keeps the batch out of the platform store."""
        compiled = artifact(COMPILED / (rule + '.json'))
        payload = self.case(rule, name)
        now = timestamp(payload['evaluate_at']) + dt.timedelta(seconds=windows * payload['window_seconds'])
        platform: Any = Recorder() if capture else Intake(self.store, now)
        query = FixtureQuery(compiled, shift(payload, windows))
        result = tick(self.index, compiled, RESOURCE, self.cursor, query, platform,
                      now=now, window_seconds=payload['window_seconds'])
        return Run(result, query, platform, compiled, now)

    def incidents(self) -> dict[str, Any]:
        return self.store.status()['incidents']


class CompilerReaderTests(unittest.TestCase):
    """The reader above may read only what the compiler is able to write."""

    def artifacts(self) -> dict[str, dict[str, Any]]:
        return {path.stem: artifact(path) for path in sorted(COMPILED.glob('*.json'))}

    def test_every_shipped_artifact_carries_the_clauses_and_projections_the_reader_assumes(self) -> None:
        artifacts = self.artifacts()
        self.assertEqual(['audit-trail-disable', 'process-marker'], sorted(artifacts),
                         'a newly compiled rule needs its fixtures and its cases named here too')
        for name, document in artifacts.items():
            with self.subTest(rule=name):
                self.assertIn(WHERE_WINDOW, document['sql'])
                for clause in WHERE_SCOPE:
                    self.assertIn(clause, document['sql'])
                for field in document['required_fields']:
                    self.assertIn(PROJECTIONS[field], document['sql'])
                self.assertTrue(Reader(predicate_source(document['sql']), document['required_fields']).parse())

    def test_shapes_this_reader_must_not_guess_are_refused(self) -> None:
        document = self.artifacts()['process-marker']
        source, fields = predicate_source(document['sql']), document['required_fields']
        for text, reason in ((source.replace('ILIKE', 'LIKE'), 'ILIKE'),
                             (source.replace('Image ILIKE', 'Host ILIKE'), 'outside the artifact'),
                             ("CommandLine ILIKE 'unterminated", 'Unterminated LIKE'),
                             (source + ' extra', 'Trailing tokens')):
            with self.subTest(shape=reason):
                with self.assertRaises(ValueError) as caught:
                    Reader(text, fields).parse()
                self.assertIn(reason, str(caught.exception))

    def test_like_semantics_are_the_backends(self) -> None:
        self.assertTrue(match_pattern('/opt/lo-fixture', '%/lo-fixTURE'), 'ILIKE is case-insensitive')
        self.assertTrue(match_pattern('a-b', 'a_b'))
        self.assertFalse(match_pattern('ab', 'a_b'), '_ is exactly one character')
        self.assertTrue(match_pattern('x audit_log y', '%audit\\_log%'))
        self.assertFalse(match_pattern('x auditl og y', '%audit\\_log%'), '\\_ is a literal underscore')
        with self.assertRaises(ValueError):
            match_pattern('anything', '%nonsense%\\q')


class FixtureExpectationTests(unittest.TestCase):
    """Each fixture says what it expects to produce, and the compiled SQL has to agree."""

    def test_every_case_matches_its_own_expectation(self) -> None:
        checked = []
        for rule in sorted(path.name for path in FIXTURES.iterdir() if path.is_dir()):
            document = artifact(COMPILED / (rule + '.json'))
            for case in fixtures(rule):
                with self.subTest(rule=rule, case=case['case']):
                    self.assertEqual(case['expect'],
                                     counts(document, case['rows'],
                                            window_parameters(case, document['dataset'])),
                                     f'{rule}/{case["case"]} does not read the way its own file says')
                    checked.append(f'{rule}/{case["case"]}')
        self.assertEqual(10, len(checked), 'the committed fixture set changed size; move the count here'
                                          ' and the case list in components/control/sigma/conformance.md')


class RunnerVerdictTests(Harness):
    """The docs/COMPONENTS.md §5 scenario, driven through the real `tick()`."""

    def test_positive_files_one_finding_and_the_near_miss_resolves_it(self) -> None:
        first = self.drive('audit-trail-disable', 'positive')
        self.assertEqual('delivered', first.result)
        self.assertEqual({'open': 1}, self.incidents(), 'one security incident; coverage recovered quietly')
        self.assertEqual('delivered', self.drive('audit-trail-disable', 'negative', windows=1).result)
        self.assertEqual({'resolved': 1}, self.incidents(), 'the same condition resolved, not a new incident')

    def test_absent_sensor_opens_coverage_and_never_resolves_the_finding_it_cannot_see(self) -> None:
        self.drive('audit-trail-disable', 'positive')
        run = self.drive('audit-trail-disable', 'absent', windows=1)
        events = [json.loads(row['payload']) for row in self.store.records('events')]
        later = [row for row in events if row['window']['end'] == utc_text(run.now)]
        finding = 'sigma.' + run.compiled['rule_id']
        self.assertEqual([finding + '.coverage'], [row['rule_id'] for row in later],
                         'the empty window speaks once, about the source and not about the threat')
        self.assertEqual('firing', later[0]['status'])
        self.assertEqual({'open': 2}, self.incidents(), 'the finding from the previous window stays open')

    def test_missing_mapped_field_is_a_coverage_finding_not_a_negative(self) -> None:
        self.drive('process-marker', 'unmapped')
        stored = [json.loads(row['payload']) for row in self.store.records('events')]
        finding = 'sigma.' + artifact(COMPILED / 'process-marker.json')['rule_id']
        self.assertEqual([finding + '.coverage'], [row['rule_id'] for row in stored],
                         'one event about the window, and it is the coverage one')
        self.assertEqual('firing', stored[0]['status'])
        self.assertEqual({'open': 1}, self.incidents(),
                         'the gap is the state; a dropped field is never read as a negative result')

    def test_window_edges_are_half_open_so_a_row_is_never_counted_twice(self) -> None:
        run = self.drive('process-marker', 'boundaries')
        parameters = run.query.seen[0]
        self.assertEqual(1788955140000000000, parameters['start_ns'], '11:59:00Z')
        self.assertEqual(1788955200000000000, parameters['end_ns'], '12:00:00Z, exclusive')
        self.assertEqual(1, counts(run.compiled, self.case('process-marker', 'boundaries')['rows'],
                                  parameters)['source_count'], 'the row on the upper edge belongs to the'
                                                               ' next window, and was not asked about twice')
        self.assertEqual('delivered', run.result)

    def test_scope_filters_keep_other_resources_and_datasets_out_of_the_count(self) -> None:
        run = self.drive('process-marker', 'scope')
        self.assertEqual({'source_count': 1, 'usable_count': 1, 'match_count': 1},
                         counts(run.compiled, self.case('process-marker', 'scope')['rows'],
                                run.query.seen[0]))

    def test_replays_never_multiply_findings(self) -> None:
        """Same rule, same resource, four firing windows: one incident, one identity per window."""
        for step in range(4):
            self.assertEqual('delivered', self.drive('audit-trail-disable', 'positive', windows=step).result)
        self.assertEqual({'open': 1}, self.incidents(), 'four firing windows are still one open incident')
        rows = self.store.records('events')
        keys = {(row['source'], row['source_event_id']) for row in rows}
        self.assertEqual(len(keys), len(rows), 'every stored event carries a distinct identity')
        self.assertEqual(8, len(rows), 'two events per window, and no accumulation beyond that')
        self.assertEqual({'open': 1}, Store(self.root / 'state.db').status()['incidents'],
                         'a restart reads the same state, because it is the same rows')

    def test_a_lost_acknowledgement_replays_the_batch_without_requerying_or_refinding(self) -> None:
        compiled = artifact(COMPILED / 'audit-trail-disable.json')
        payload = self.case('audit-trail-disable', 'positive')
        now = timestamp(payload['evaluate_at'])
        query = FixtureQuery(compiled, payload['rows'])
        with self.assertRaises(TransportError):
            tick(self.index, compiled, RESOURCE, self.cursor, query,
                 Intake(self.store, now, lose_acknowledgement=True), now=now, window_seconds=60)
        self.assertEqual({}, self.incidents(), 'the batch is owed, so nothing was acknowledged')
        self.assertEqual('delivered', tick(self.index, compiled, RESOURCE, self.cursor, query,
                                          Intake(self.store, now), now=now, window_seconds=60))
        self.assertEqual(1, query.calls, 'the exact stored batch was replayed, not re-evaluated')
        self.assertEqual(2, len(self.store.records('events')), 'the replay added no second event')
        self.assertEqual({'open': 1}, self.incidents(), 'one finding, from the window it belongs to')


class MaintenanceWindowTests(Harness):
    """The window `privileged-shell-spawn.yaml` needs is a suppression on the send, not a timestamp."""

    def setUp(self) -> None:
        super().setUp()
        run = self.drive('audit-trail-disable', 'positive', capture=True)
        self.compiled, self.now = run.compiled, run.now
        self.batch = run.platform.events()
        self.finding = 'sigma.' + self.compiled['rule_id']

    def declare(self, *, rule_id: str | None = None) -> dict[str, Any]:
        return suppression.declare_window(self.store, {
            'rule_id': self.finding if rule_id is None else rule_id,
            'starts_at': '2026-09-09T12:00:00Z', 'ends_at': '2026-09-09T16:00:00Z',
            'reason': 'planned work on the audit host'}, HUMAN, now=self.now)

    def file(self, rule_id: str) -> dict[str, Any]:
        return suppression.file_event(self.store, self.batch[rule_id], PRODUCER, now=self.now)

    def delivery(self, identifier: str) -> dict[str, Any]:
        """The outbox row and its refusal line, read with raw sqlite like `tests/test_maintenance_windows`."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            row = db.execute('SELECT status FROM outbox WHERE id=?', (identifier,)).fetchone()
            refused = db.execute('SELECT reason FROM notification_suppressions WHERE outbox_id=?',
                                 (identifier,)).fetchone()
        return {'status': row['status'], 'reason': None if refused is None else refused['reason']}

    def test_a_window_over_the_rule_refuses_the_send_and_keeps_the_finding(self) -> None:
        self.declare()
        result = self.file(self.finding)
        self.assertTrue(result['suppressed'])
        self.assertEqual('maintenance-window', result['decision'].cause)
        self.assertIn(self.finding, result['decision'].reason)
        record = self.delivery(result['delivery'])
        self.assertEqual('dead', record['status'])
        self.assertIn('maintenance-window', record['reason'])
        self.assertEqual({'open': 1}, self.incidents(),
                         'a window silences a page and not a record: the finding is still listable')
        stored = [json.loads(row['payload'])['rule_id'] for row in self.store.records('events')]
        self.assertIn(self.finding, stored)

    def test_a_window_over_the_rule_does_not_cover_its_coverage_event(self) -> None:
        self.declare()
        self.assertFalse(self.file(self.finding + '.coverage')['suppressed'],
                         'planned work is not a licence to hide that the producer went silent')

    def test_a_window_over_another_rule_silences_nothing(self) -> None:
        self.declare(rule_id='sigma.00000000-0000-4000-8000-000000000000')
        self.assertFalse(self.file(self.finding)['suppressed'])

    def transition(self, status: str, start: str, end: str) -> dict[str, Any]:
        """A second verdict from the same rule, in a later window, with its identity and evidence moved."""
        original = self.batch[self.finding]
        window = {'start': start, 'end': end}
        return dict(original, status=status, window=window, observed_at=end,
                    source_event_id=digest([self.finding, original['rule_version'], RESOURCE, window]),
                    evidence=[dict(original['evidence'][0], window=window)])

    def test_a_finding_pages_again_once_the_window_is_revoked(self) -> None:
        self.declare()
        self.assertTrue(self.file(self.finding)['suppressed'])
        window = suppression.live_windows(self.store, now=self.now)['windows'][0]
        suppression.revoke_window(self.store, window['id'], HUMAN, now=self.now)
        recovery = self.transition('resolved', '2026-09-09T12:01:00+00:00', '2026-09-09T12:02:00+00:00')
        result = suppression.file_event(self.store, recovery, PRODUCER,
                                       now=timestamp(recovery['window']['end']))
        self.assertFalse(result['suppressed'], 'a revoked window stops applying; the next transition pages')
        self.assertEqual({'resolved': 1}, self.incidents(), 'and the incident closes on its own verdict')


class MeasurementReportingTests(unittest.TestCase):
    """`N rules shipped, M unmeasured`, with every absent number counted the pessimistic way."""

    def test_the_shipped_pack_reports_what_it_actually_is(self) -> None:
        answer = measurement_report(sorted(COMPILED.glob('*.json')))
        self.assertEqual({'shipped': 2, 'measured': 0, 'unmeasured': 2},
                         {key: answer[key] for key in ('shipped', 'measured', 'unmeasured')})
        self.assertEqual('2 rules shipped, 2 unmeasured', answer['headline'])
        self.assertEqual(sorted(answer['rules'], key=lambda item: item['rule_id']), answer['rules'],
                         'the report is deterministic, so two runs on one tree print one number')
        for rule in answer['rules']:
            self.assertTrue(rule['reason'], 'an unmeasured rule must say why, in the report an operator'
                                           ' reads')

    def test_a_malformed_or_absent_measurement_block_is_unmeasured_never_measured(self) -> None:
        cases = ((None, 'no measurement'),
                 ({}, 'does not know'),
                 ({'status': 'measured'}, 'missing'),
                 ({'status': 'measured', 'false_positives': '0', 'window': 'w', 'population': 'p',
                   'measured_on': 'd', 'source': 's'}, 'missing'),
                 ({'status': 'measured', 'false_positives': 0, 'window': 'w', 'population': 'p',
                   'measured_on': 'd', 'source': ''}, 'missing'),
                 ({'status': 'counted'}, 'does not know'))
        for block, marker in cases:
            document = {'rule_id': 'x'} if block is None else {'rule_id': 'x', 'measurement': block}
            with self.subTest(block=str(block)[:44]):
                answer = measurement_status(document)
                self.assertEqual('unmeasured', answer['status'])
                self.assertIn(marker.split()[0], answer['reason'])

    def test_one_complete_block_is_counted_as_measured(self) -> None:
        answer = measurement_status({'rule_id': 'x', 'measurement': {
            'status': 'measured', 'false_positives': 3, 'window': '7d', 'population': 'one host',
            'measured_on': '2026-09-09', 'source': 'docs/evidence'}})
        self.assertEqual('measured', answer['status'])
        self.assertEqual(3, answer['false_positives'])
        mixed = measurement_report([{'rule_id': 'x', 'measurement': {
            'status': 'measured', 'false_positives': 1, 'window': '1d', 'population': 'one host',
            'measured_on': '2026-09-09', 'source': 'docs/evidence'}},
            {'rule_id': 'y', 'measurement': {'status': 'unmeasured', 'reason': 'nope'}}])
        self.assertEqual({'shipped': 2, 'measured': 1, 'unmeasured': 1},
                         {key: mixed[key] for key in ('shipped', 'measured', 'unmeasured')})
        self.assertEqual('2 rules shipped, 1 unmeasured', mixed['headline'])
