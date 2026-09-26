"""correlation: routing answers "who owns this incident, and on what declaration" — from the declaration only.

`legacy:aiops/incidents` is 474 lines and the port table takes one half of it across: an incident names *who
owns it and why*. The other half — a second incident store — is why that component was abandoned as a
store, and nothing here reopens it: this file changes no platform-state schema, adds no table and moves no
state. The incident already names its resource (`incidents.resource_id`, a declared UUID), and the declared
plane is the only place an owner can be written down.

Two refusals are the substance of this card's routing, and both are tested from the negative side:

* **never an owner inferred from a name.** An alias says how a resource is *found*; whoever owns the box is
  a different claim, and `resource_info` above this function already prints host names for the operator. If
  routing could read a hostname it would produce a confident, wrong, un-declared answer, so the test
  declares a resource whose only human-readable text is a hostname and asserts the owner line says
  "nobody declared one" while the name line prints the name.
* **the typed `owner` field, the index column that stores it and the read order are one change.**
  `local_observe/inventory/schemas/declared.json` closes the resource object with
  `additionalProperties: false` and declares `owner` as one bounded string, and `inventory/index.py`
  stores it in `resources.owner` — a built-index schema step, so `SCHEMA_VERSION` is 2 and a version-1
  index is refused with the rebuild command rather than read as if nobody had an owner. `owner_info`
  routes on that column first and falls back to `attributes['owner']`, which is an open map of scalars
  (`common.json`) and therefore can still hold a boolean: that case keeps its "not a name" sentence, and
  a string read from the map carries the deprecation sentence so the two spellings never look alike.
  correlation followups (2026-09-10) drafted the field alone and withdrew it before landing, because a read of ownership
  goes through the *built* index and a field it drops is validated, digested and then ignored — accepted
  and ignored being the one shape this product refuses. `DeclarationSchemaTests` pins the field and the
  stored columns; `TypedOwnerDeclarationTests` pins the accepted shapes, the refusals and the read order.

Nothing durable is written about ownership, and the reason is stated rather than assumed: `incidents` may
not gain a column this wave (brief correction 3) and a column on the grouping table would carry an owner
only for incidents that were grouped, which is the minority. So the label is a *read* of the declaration the
platform already consults per page, and the durable artefact beside it — the rationale row — names the
declaration digest it was composed against. A resource that is undeclared later therefore loses its owner
label and keeps its explanation, which is the degradation correlation chose and reported.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import InvalidInventory, read_document, timestamp, utc_text
from local_observe.platform import presentation
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-10T12:00:00Z')
PRODUCER = Actor('routing-fixture', 'producer')
SCHEMA = ROOT / 'local_observe' / 'inventory' / 'schemas' / 'declared.json'
COMMON = ROOT / 'local_observe' / 'inventory' / 'schemas' / 'common.json'

#: What `owner_info` appends to an owner read out of the open `attributes` map instead of the typed field.
#: Spelled out again here rather than imported from the product, so the wording is a pin, not a restatement.
ATTRIBUTES_OWNER = '(declared under attributes — declare it as owner:)'

#: Owner spellings `declared.json` admits. Each one is a routing answer, printed exactly as declared.
OWNER_SHAPES = ('team-platform', 'team.platform', 'Team_Platform', 'oncall+alerts', 'storage crew',
                'a', 'a' * 128)


def attributes_label(name: str) -> str:
    """The label for an owner declared only under `attributes` — the deprecated spelling, said out loud."""
    return f'{name} {ATTRIBUTES_OWNER}'


def identifier(name: str) -> str:
    """A stable synthetic UUID for a synthetic name, never a real estate id."""
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'routing-fixture/' + name))


class RoutingFixture(unittest.TestCase):
    """One declaration, one store, and the incident view over both."""

    resources: list[dict] = []

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': [dict(item) for item in self.resources]},
                    self.index_path, 'routing-rev-1', now=NOW)
        self.store = Store(self.root / 'state.db')

    def resource(self, name: str, kind: str = 'service', attributes: dict | None = None,
                 aliases: list[dict] | None = None,
                 relations: tuple[tuple[str, str], ...] = ()) -> dict:
        return {'id': identifier(name), 'kind': kind, 'name': name,
                'aliases': aliases or [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
                'attributes': attributes if attributes is not None else {},
                'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}

    def open_incident(self, name: str, rule: str, *, at: dt.datetime = NOW) -> dict:
        """File one firing event about `name` with no grouping installed, and return its incident row."""
        window = {'start': utc_text(at - dt.timedelta(minutes=1)), 'end': utc_text(at)}
        self.store.intake(event(PRODUCER.identity, identifier(name), rule, 'availability', 'firing',
                               window, {'rule_id': rule}, query_type='gatus-result'), PRODUCER, now=at)
        rows = presentation.records(self.store, 'incidents', self.store.records('incidents'),
                                   self.index_path)
        self.assertEqual(len(rows), 1)
        return rows[0]


class DeclaredOwnerTests(RoutingFixture):
    """Every answer the declaration can produce, as its own sentence.

    Every owner below is declared the old way, under `attributes`, so each label carries the deprecation
    sentence; `TypedOwnerDeclarationTests` holds the typed field's answers.
    """

    resources = [
        {'id': identifier('team-owner'), 'kind': 'service', 'name': 'team-owner',
         'aliases': [{'type': 'service.name', 'value': 'team-owner', 'scope': 'fixture'}],
         'attributes': {'owner': 'team-platform'}, 'relations': []},
        {'id': identifier('no-owner'), 'kind': 'service', 'name': 'no-owner',
         'aliases': [{'type': 'service.name', 'value': 'no-owner', 'scope': 'fixture'}],
         'attributes': {'environment': 'fixture'}, 'relations': []},
        {'id': identifier('number-owner'), 'kind': 'service', 'name': 'number-owner',
         'aliases': [{'type': 'service.name', 'value': 'number-owner', 'scope': 'fixture'}],
         'attributes': {'owner': 7}, 'relations': []},
        {'id': identifier('bool-owner'), 'kind': 'service', 'name': 'bool-owner',
         'aliases': [{'type': 'service.name', 'value': 'bool-owner', 'scope': 'fixture'}],
         'attributes': {'owner': True}, 'relations': []},
        {'id': identifier('blank-owner'), 'kind': 'service', 'name': 'blank-owner',
         'aliases': [{'type': 'service.name', 'value': 'blank-owner', 'scope': 'fixture'}],
         'attributes': {'owner': '   '}, 'relations': []},
        {'id': identifier('long-owner'), 'kind': 'service', 'name': 'long-owner',
         'aliases': [{'type': 'service.name', 'value': 'long-owner', 'scope': 'fixture'}],
         'attributes': {'owner': 'oncall ' * 60}, 'relations': []},
        {'id': identifier('wrapped-owner'), 'kind': 'service', 'name': 'wrapped-owner',
         'aliases': [{'type': 'service.name', 'value': 'wrapped-owner', 'scope': 'fixture'}],
         'attributes': {'owner': '  storage\ncrew  '}, 'relations': []},
        {'id': identifier('hostname-only'), 'kind': 'service', 'name': 'worker-1',
         'aliases': [{'type': 'hostname', 'value': 'demo-host-01.internal', 'scope': 'fixture'}],
         'attributes': {}, 'relations': []},
    ]

    def label_for(self, name: str) -> str:
        return presentation.owner_info(self.index_path, [identifier(name)])[identifier(name)]

    def test_a_declared_owner_is_the_declaration_s_word(self):
        self.assertEqual(self.label_for('team-owner'), attributes_label('team-platform'))

    def test_an_undeclared_owner_says_nobody_declared_one(self):
        self.assertEqual(self.label_for('no-owner'), 'No owner declared')

    def test_a_blank_owner_is_no_owner_and_not_an_empty_label(self):
        self.assertEqual(self.label_for('blank-owner'), 'No owner declared')

    def test_a_scalar_that_is_not_a_name_is_not_printed_as_one(self):
        """`common.json` admits numbers and booleans into `attributes`; `true` is nobody's on-call."""
        self.assertEqual(self.label_for('number-owner'), 'Declared owner is not a name')
        self.assertEqual(self.label_for('bool-owner'), 'Declared owner is not a name')

    def test_a_long_owner_is_bounded_the_way_every_label_here_is(self):
        """The bound is the whole label's, so the name gives way and the deprecation sentence survives."""
        label = self.label_for('long-owner')
        self.assertLessEqual(len(label), 160)
        self.assertTrue(label.startswith('oncall'))
        self.assertTrue(label.endswith(ATTRIBUTES_OWNER))

    def test_surrounding_whitespace_and_newlines_are_not_carried_into_a_label(self):
        self.assertEqual(self.label_for('wrapped-owner'), attributes_label('storage crew'))

    def test_an_undeclared_resource_is_named_as_one(self):
        import uuid
        absent = str(uuid.uuid4())
        self.assertEqual(presentation.owner_info(self.index_path, [absent])[absent], 'Not declared')

    def test_an_incident_that_names_no_resource_says_so(self):
        self.assertEqual(presentation.owner_info(self.index_path, [None])[None],
                        'No resource on this incident')

    def test_no_index_configured_is_a_different_answer_from_no_owner(self):
        self.assertEqual(presentation.owner_info(None, [identifier('team-owner')])
                        [identifier('team-owner')], 'Ownership not configured')
        self.assertEqual(presentation.owner_info('', [identifier('team-owner')])
                        [identifier('team-owner')], 'Ownership not configured')

    def test_an_index_that_will_not_open_is_neither_of_the_above(self):
        broken = self.root / 'not-an-index.db'
        Store(broken)                                        # a real SQLite file with the wrong tables
        self.assertEqual(presentation.owner_info(broken, [identifier('team-owner')])
                        [identifier('team-owner')], 'Ownership unavailable')

    def test_the_owner_of_a_resource_named_only_by_a_hostname_is_still_undeclared(self):
        """The routing refusal, from the negative side: the name is available and the owner is not.

        `demo-host-01.internal` is a hostname alias and `worker-1` is the declared name; a routing rule
        that read either would produce a confident answer nobody wrote down. The resource line prints the
        name; the owner line says the declaration is silent.
        """
        row = self.open_incident('hostname-only', 'worker.down')
        self.assertEqual(row['display']['owner_name'], 'No owner declared')
        self.assertEqual(row['display']['resource_name'], 'worker-1')
        self.assertNotIn('demo-host-01', json.dumps(row['display']))

    def test_the_owner_line_appears_on_the_incident_view_and_nowhere_else(self):
        row = self.open_incident('team-owner', 'owner.down')
        self.assertEqual(row['display']['owner_name'], attributes_label('team-platform'))
        for table in ('events', 'outbox', 'actions', 'executions'):
            for other in presentation.records(self.store, table, self.store.records(table),
                                             self.index_path):
                with self.subTest(table=table):
                    self.assertNotIn('owner_name', other['display'])

    def test_an_incident_about_an_undeclared_uuid_is_not_reported_as_declared(self):
        """Intake admits any canonical UUID (§4.2's unresolved case), so the view must say what it found."""
        import uuid
        absent = str(uuid.uuid4())
        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        self.store.intake(event(PRODUCER.identity, absent, 'gone.down', 'availability', 'firing', window,
                               {'rule_id': 'gone.down'}, query_type='gatus-result'), PRODUCER, now=NOW)
        row = presentation.records(self.store, 'incidents', self.store.records('incidents'),
                                  self.index_path)[0]
        self.assertEqual(row['display']['owner_name'], 'Not declared')


class TypedOwnerDeclarationTests(RoutingFixture):
    """The typed field end to end: admitted at the build, stored in its column, read before the map.

    correlation followups's withdrawal was about the gap between these three; each assertion below closes one half of
    it.
    """

    resources = ([{'id': identifier(f'typed-{position}'), 'kind': 'service', 'name': f'typed-{position}',
                   'aliases': [{'type': 'service.name', 'value': f'typed-{position}', 'scope': 'fixture'}],
                   'attributes': {}, 'relations': [], 'owner': shape}
                  for position, shape in enumerate(OWNER_SHAPES)]
                 + [
                     {'id': identifier('both-spellings'), 'kind': 'service', 'name': 'both-spellings',
                      'aliases': [{'type': 'service.name', 'value': 'both-spellings', 'scope': 'fixture'}],
                      'attributes': {'owner': 'team-attributes'}, 'relations': [],
                      'owner': 'team-typed'},
                     {'id': identifier('map-only'), 'kind': 'service', 'name': 'map-only',
                      'aliases': [{'type': 'service.name', 'value': 'map-only', 'scope': 'fixture'}],
                      'attributes': {'owner': 'team-attributes'}, 'relations': []},
                     {'id': identifier('typed-nobody'), 'kind': 'service', 'name': 'typed-nobody',
                      'aliases': [{'type': 'service.name', 'value': 'typed-nobody', 'scope': 'fixture'}],
                      'attributes': {'environment': 'fixture'}, 'relations': []}])

    def label_for(self, name: str) -> str:
        """The owner label this declaration produces for one resource, read through the built index."""
        return presentation.owner_info(self.index_path, [identifier(name)])[identifier(name)]

    def test_every_admitted_spelling_is_stored_in_its_column(self):
        """Built, not merely accepted: the stored column is the first proof, the label the second one."""
        with index.readonly(self.index_path) as db:
            stored = dict(db.execute('SELECT id, owner FROM resources'))
        for position, shape in enumerate(OWNER_SHAPES):
            with self.subTest(owner=shape):
                self.assertEqual(stored[identifier(f'typed-{position}')], shape)

    def test_every_admitted_spelling_routes_as_written(self):
        asked = [identifier(f'typed-{position}') for position in range(len(OWNER_SHAPES))]
        labels = presentation.owner_info(self.index_path, asked)
        for position, shape in enumerate(OWNER_SHAPES):
            with self.subTest(owner=shape):
                self.assertEqual(labels[identifier(f'typed-{position}')], shape,
                                'a typed owner is printed as declared, with no deprecation sentence')

    def test_a_resource_that_names_nobody_stores_null_and_says_no_owner(self):
        """NULL is the undeclared case, never an empty string that a reader could mistake for one."""
        with index.readonly(self.index_path) as db:
            row = db.execute('SELECT owner FROM resources WHERE id=?',
                             (identifier('typed-nobody'),)).fetchone()
        self.assertIsNone(row['owner'])
        self.assertEqual(self.label_for('typed-nobody'), 'No owner declared')

    def test_naming_an_owner_moves_the_declaration_digest(self):
        """The owner is declaration content: `normalized()` keeps it, so the digest states who was named."""
        base = self.resource('digest-owner', attributes={'environment': 'fixture'})
        unnamed = index.build({'schema_version': 1, 'resources': [dict(base)]},
                              self.root / 'unnamed.db', 'digest-rev', now=NOW)
        named = index.build({'schema_version': 1, 'resources': [dict(base, owner='team-platform')]},
                            self.root / 'named.db', 'digest-rev', now=NOW)
        self.assertNotEqual(unnamed['declaration_sha256'], named['declaration_sha256'])

    def test_the_typed_field_is_read_before_the_attributes_spelling(self):
        self.assertEqual(self.label_for('both-spellings'), 'team-typed')

    def test_an_owner_declared_only_under_attributes_says_so_in_the_label(self):
        self.assertEqual(self.label_for('map-only'), attributes_label('team-attributes'))

    def test_a_shape_that_is_not_one_bounded_line_is_refused_at_the_build(self):
        """The field is typed, so the refusals belong to the build and not to the view.

        `'/etc/passwd'` and `'<b>'` are what a value that is nobody's on-call looks like, and `7`, `None`
        and `True` are what the open map next door still admits.
        """
        for position, shape in enumerate(('', ' leading', 'team\nplatform', 'team-x\n', 'a\n',
                                          'team-x\r\n', 'x' * 129, 'ünknown', '/etc/passwd', '<b>',
                                          7, None, True)):
            resource = self.resource('typed-refusal', attributes={'environment': 'fixture'})
            resource['owner'] = shape
            output = self.root / f'refused-{position}.db'
            with self.subTest(owner=repr(shape)):
                with self.assertRaises(InvalidInventory):
                    index.build({'schema_version': 1, 'resources': [resource]},
                                output, 'refusal-rev', now=NOW)
                self.assertFalse(output.exists(),
                                 'a refused declaration writes no index at all')


class GroupedRoutingTests(RoutingFixture):
    """A group routes on the declaration that opened it, not on whichever symptom arrived last."""

    resources = [
        {'id': identifier('host'), 'kind': 'host', 'name': 'host',
         'aliases': [{'type': 'service.name', 'value': 'host', 'scope': 'fixture'}],
         'attributes': {'owner': 'team-platform'}, 'relations': []},
        {'id': identifier('api'), 'kind': 'service', 'name': 'api',
         'aliases': [{'type': 'service.name', 'value': 'api', 'scope': 'fixture'}],
         'attributes': {'owner': 'team-api'},
         'relations': [{'type': 'runs-on', 'target': identifier('host')}]},
    ]

    def verdict(self, name: str, rule: str, *, at: dt.datetime = NOW) -> dict:
        window = {'start': utc_text(at - dt.timedelta(minutes=1)), 'end': utc_text(at)}
        return event(PRODUCER.identity, identifier(name), rule, 'availability', 'firing', window,
                     {'rule_id': rule}, query_type='gatus-result')

    def grouped(self) -> dict:
        self.store.intake(self.verdict('api', 'api.down'), PRODUCER, now=NOW,
                         admission=self.store.grouping_admission(self.index_path, PRODUCER, now=NOW))
        self.store.intake(self.verdict('host', 'host.down'), PRODUCER, now=NOW,
                         admission=self.store.grouping_admission(self.index_path, PRODUCER, now=NOW))
        return presentation.records(self.store, 'incidents', self.store.records('incidents'),
                                   self.index_path)[0]

    def test_the_group_routes_on_the_resource_that_opened_it(self):
        row = self.grouped()
        self.assertEqual(row['display']['owner_name'], attributes_label('team-api'),
                        'the anchor is whose declaration opened the incident')
        self.assertEqual(row['grouping']['total'], 2)
        self.assertEqual([member['resource_id'] for member in row['grouping']['members']],
                        [identifier('api'), identifier('host')],
                        'the member keeps its own resource, and its own owner is one read away')

    def test_the_member_resources_are_listed_so_the_other_owner_is_reachable(self):
        row = self.grouped()
        self.assertIn(identifier('host'), json.dumps(row['grouping']))

    def test_the_label_follows_whichever_incident_was_opened_first(self):
        """The anchor is the owner's identity, in both orders, and a group has exactly one of them."""
        self.store.intake(self.verdict('host', 'host.down'), PRODUCER, now=NOW,
                         admission=self.store.grouping_admission(self.index_path, PRODUCER, now=NOW))
        later = NOW + dt.timedelta(seconds=30)
        self.store.intake(self.verdict('api', 'api.down', at=later), PRODUCER, now=later,
                         admission=self.store.grouping_admission(self.index_path, PRODUCER, now=later))
        rows = presentation.records(self.store, 'incidents', self.store.records('incidents'),
                                   self.index_path)
        self.assertEqual(len(rows), 1, 'the api joined the host incident, which was opened first')
        self.assertEqual(rows[0]['display']['owner_name'], attributes_label('team-platform'))


class DeclarationSchemaTests(unittest.TestCase):
    """The typed field, the closed object around it and the index column that stores it.

    correlation followups (2026-09-10) drafted the schema field alone and withdrew it: with no owner column in the built
    index, a declaration naming one would have been accepted and never shown. typed inventory records lands field,
    column
    and read order together, and these assertions are the shape that combination pins.
    """

    def document(self, **fields: dict) -> dict:
        """One minimal legal resource, with `fields` added or replaced on its object."""
        resource = {'id': identifier('schema-probe'), 'kind': 'service', 'name': 'schema-probe',
                    'aliases': [{'type': 'service.name', 'value': 'schema-probe', 'scope': 'fixture'}],
                    'attributes': {}, 'relations': []}
        resource.update(fields)
        return {'schema_version': 1, 'resources': [resource]}

    def test_the_declared_resource_object_carries_one_bounded_owner_and_no_other_field(self):
        schema = read_document(SCHEMA)
        resource = schema['properties']['resources']['items']
        self.assertIs(resource['additionalProperties'], False)
        self.assertEqual(resource['properties']['owner'],
                        {'type': 'string', 'minLength': 1, 'maxLength': 128,
                         'pattern': r'^[A-Za-z0-9][A-Za-z0-9._@+ -]{0,127}(?![\s\S])',
                         'description': "The on-call identity the operator's overlay declares for this "
                                         'resource (a team, an account or a mailbox-shaped string), never '
                                         'a hostname and never inferred from one.'})
        self.assertEqual(sorted(resource['required']),
                        ['aliases', 'attributes', 'id', 'kind', 'name', 'relations'])

    def test_the_owner_is_optional_and_a_misspelling_of_it_is_refused_at_the_build(self):
        """A closed object means `onwer:` is an error, not a typo that silently names nobody."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'owner-absent.db'
            index.build(self.document(), path, 'no-owner-rev', now=NOW)     # optional: absent still builds
            self.assertEqual(presentation.owner_info(path, [identifier('schema-probe')])
                            [identifier('schema-probe')], 'No owner declared')
            for key in ('onwer', 'owners', 'Owner', 'on-call'):
                with self.subTest(key=key):
                    with self.assertRaises(InvalidInventory):
                        index.build(self.document(**{key: 'team-platform'}),
                                    Path(root) / f'{key}.db', 'typo-rev', now=NOW)

    def test_the_built_index_stores_the_owner_as_its_own_last_column(self):
        """The stored-column fact correlation followups's withdrawal rested on, asserted from a built file, not a comment."""
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'columns.db'
            index.build({'schema_version': 1, 'resources': []}, path, 'columns-rev', now=NOW)
            with index.readonly(path) as db:
                columns = [row[1] for row in db.execute('PRAGMA table_info(resources)')]
        self.assertEqual(columns, ['id', 'kind', 'name', 'attributes', 'credential_refs', 'owner'])

    def test_attributes_is_still_an_open_scalar_map_which_is_why_the_old_spelling_needs_two_sentences(self):
        """`common.json` admits numbers and booleans into `attributes`, which is why an owner declared there
        can be `true` and why `owner_info` keeps its `not a name` sentence for that spelling."""
        common = read_document(COMMON)
        attributes = common['$defs']['attributes']
        self.assertIsInstance(attributes['additionalProperties']['type'], list)
        self.assertIn('string', attributes['additionalProperties']['type'])
        self.assertNotIn('owner', attributes.get('properties', {}))

    def test_the_example_declaration_declares_no_owner_so_the_shipped_view_is_the_unowned_case(self):
        """The product's own example is what a new installation sees; it names nobody, in either spelling."""
        example = read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml')
        for item in example['resources']:
            with self.subTest(resource=item['name']):
                self.assertNotIn('owner', item)
                self.assertNotIn('owner', item.get('attributes') or {})


if __name__ == '__main__':
    unittest.main()
