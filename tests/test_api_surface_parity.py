"""A capability that stays off HTTP has to say why, in a word the census owns, and point at what exists instead.

`tests/test_api_openapi_conformance.py` already fails a census row that disagrees with the OpenAPI document or
with a served route — the two files' *agreement*. It has nothing to say about an absence: for a row whose
surface is `cli`, `ui` or `mcp` it checks the row is well-formed and stops there, which is how a census
silently becomes a list of things nobody will explain. This file closes that half for the two owner areas it is
scoped to, and it is written as a gate rather than a report so that widening it to the remaining areas is an
edit to one tuple.

Four rules, each one a way an "excluded from HTTP" claim can be false:

1. **Every implemented non-HTTP row answers for itself** with exactly one of `http_via` (an HTTP operation
   already answers this capability, so the missing route is a decision that has been kept) or `no_http` (one
   reason from the closed `vocabularies.exclusion_reasons`). Not both, and neither is allowed to be absent.
2. **A reason must be a reason the file defines.** A row that invents `not_yet` has said `planned` in prose,
   and `planned` is a different row status with a different meaning: nobody has decided.
3. **An exclusion names code that exists.** The row's `module` must be a file in this repository, so "no
   route" can never be filed beside "and nothing either" — a renamed script fails the census, not an incident.
4. **Every reason in the vocabulary is used.** A fifth word nobody chooses is a hedge, and a hedge in a closed
   list is how the list stops being closed.

The mirror of rule 3 is checked too: an `http_via` target must exist, be `implemented`, and be documented as
served, because a pointer to a planned route would make the exclusion a promise rather than a fact.
"""
import os
from pathlib import Path
import unittest

import yaml

from local_observe.inventory.validation import UniqueLoader

#: The owner areas this gate covers. The remaining areas still hold unannotated rows; the brief for this work
#: scoped the census pass to these two, and the gate is written to be widened rather than to flatter anyone.
ASSIGNED_AREAS = ('administration', 'foundation')

ROOT = Path(__file__).resolve().parents[1]
CENSUS = ROOT / 'docs' / 'api' / 'coverage.yaml'
CONTRACT = ROOT / 'docs' / 'api' / 'openapi.yaml'


def load(path: Path) -> dict:
    """Return one contract document, refusing a duplicated key the way the product's config loader does."""
    return yaml.load(path.read_text(), Loader=UniqueLoader)


def census() -> list[dict]:
    return load(CENSUS)['operations']


def vocabularies() -> dict:
    return load(CENSUS)['vocabularies']


def documented() -> dict:
    """Return ``{operation_id: (method, path, x-status)}`` from the OpenAPI contract."""
    document = load(CONTRACT)
    return {operation['operationId']: (method.upper(), path, operation.get('x-status'))
            for path, item in document['paths'].items()
            for method, operation in item.items()}


class SurfaceParity(unittest.TestCase):
    """The two assigned areas, every row, and the explanation each one owes for not being a route."""

    @classmethod
    def setUpClass(cls):
        cls.rows = [row for row in census() if row['owner_area'] in ASSIGNED_AREAS]
        cls.reasons = set(vocabularies()['exclusion_reasons'])
        cls.operations = documented()
        cls.http_rows = {row['operation_id']: row for row in census() if row['surface'] == 'http'}

    def test_the_scoped_areas_are_where_the_work_was_assigned(self):
        """A renamed area would empty this file's list and turn a gate into a pass. Pin the population."""
        self.assertGreater(len(self.rows), 50)
        self.assertEqual({row['owner_area'] for row in self.rows}, set(ASSIGNED_AREAS))

    def test_every_off_http_capability_answers_with_exactly_one_explanation(self):
        for row in self.rows:
            if row['surface'] == 'http' or row['status'] != 'implemented':
                continue
            via, none = row.get('http_via'), row.get('no_http')
            name = row['operation_id']
            self.assertTrue(bool(via) ^ bool(none), f'{name}: needs exactly one of http_via/no_http')
            if none is not None:
                self.assertIn(none, self.reasons, f'{name}: {none} is not an exclusion reason')
                # The sentence, not the code, is what an operator reads at 03:00. A row that carried only the
                # word would satisfy the schema and still leave the next shift guessing.
                self.assertGreaterEqual(len(row.get('notes', '')), 60, f'{name}: no sentence with the reason')
                self.assertNotIn(none, row.get('notes', ''), f'{name}: notes repeat the reason word')
            else:
                self.assertTrue(isinstance(via, list) and via, f'{name}: http_via must name operations')
                for target in via:
                    self.assertTrue(target in self.http_rows,
                                    f'{name}: http_via {target} is not an http row')
                    self.assertEqual(self.http_rows[target]['status'], 'implemented',
                                     f'{name}: http_via {target} is not implemented')
                    self.assertEqual(self.operations.get(target, (None, None, None))[2], 'implemented',
                                     f'{name}: http_via {target} is not documented as served')

    def test_no_http_row_is_left_without_a_row_to_annotate(self):
        """The complement: a row that *is* annotated but should not be (an http row, or an unimplemented one)."""
        for row in self.rows:
            if row['surface'] == 'http' or row['status'] == 'implemented':
                continue
            self.assertIsNone(row.get('http_via') or row.get('no_http'),
                              f"{row['operation_id']}: a {row['status']} row owes no exclusion")

    def test_an_exclusion_points_at_code_that_is_in_this_repository(self):
        """`no_http` may not be filed beside a `module` nobody can open: the reason points at the real surface."""
        for row in self.rows:
            if row['surface'] == 'http':
                continue
            self.assertTrue(os.path.exists(row['module']),
                            f"{row['operation_id']}: module {row['module']} is not in this repository")

    def test_every_reason_in_the_vocabulary_is_used_by_a_real_capability(self):
        used = {row['no_http'] for row in census() if row.get('no_http')}
        self.assertEqual(used, self.reasons, 'a reason nobody chose is a hedge, not a vocabulary')

    def test_what_stays_planned_in_these_areas_is_still_visible_in_the_contract(self):
        """`planned` is the honest slot for a route this build serves nobody. It must stay named, and few."""
        planned = {row['operation_id'] for row in self.rows if row['status'] == 'planned'}
        self.assertEqual(planned, {'platform.openapi.read'})
        for name in planned:
            self.assertEqual(self.operations[name][2], 'planned', f'{name}: not documented as planned')
            self.assertIsNone(self.http_rows[name].get('http_via') or self.http_rows[name].get('no_http'),
                              f'{name}: a planned row is a promise, not an exclusion')

    def test_an_http_row_in_these_areas_carries_no_exclusion_of_its_own(self):
        """`http_via`/`no_http` describe an absence. On a row that *is* a route, they would be a contradiction."""
        for row in self.rows:
            if row['surface'] == 'http':
                self.assertIsNone(row.get('http_via') or row.get('no_http'), row['operation_id'])


if __name__ == '__main__':
    unittest.main()
