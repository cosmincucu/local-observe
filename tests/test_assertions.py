"""Named assertions keep absence and invalid inputs visibly distinct from a pass."""
from types import SimpleNamespace
import unittest

from local_observe.platform.assertions import (AssertionResult, BodyContains, HeaderEquals, StatusIs, TimingUnder,
                                               condition_mapping, condition_report, evaluate)
from local_observe.platform.state import StateError


class AssertionTests(unittest.TestCase):
    def test_inconsistent_verdict_and_detail_are_refused_at_constructor_and_evaluation(self):
        class InconsistentAssertion:
            def __init__(self, ok, detail):
                self.ok = ok
                self.detail = detail

            def check(self, subject):
                return AssertionResult('status', self.ok, self.detail)

        for ok, detail in ((True, 'not measured'), (True, 'failed'), (False, 'passed')):
            with self.subTest(ok=ok, detail=detail):
                with self.assertRaises(StateError):
                    AssertionResult('status', ok, detail)
                with self.assertRaises(StateError):
                    evaluate(None, [InconsistentAssertion(ok, detail)])
        for ok, detail in ((True, 'passed'), (False, 'failed'), (False, 'not measured')):
            with self.subTest(ok=ok, detail=detail):
                self.assertEqual(evaluate(None, [InconsistentAssertion(ok, detail)]).ok, ok)

    def test_all_failures_named_without_response_or_expectation_values(self):
        subject = SimpleNamespace(status=503, headers={'X-Ready': 'private-response'},
                                  body='private-response', timing={'total': 25})
        checks = [StatusIs(200, 'status'), HeaderEquals('x-ready', 'private-expected', 'ready-header'),
                  BodyContains('private-expected', 'body'), TimingUnder('total', 20, 'latency')]
        report = evaluate(subject, checks)
        self.assertEqual(report.failed_names, ['status', 'ready-header', 'body', 'latency'])
        self.assertFalse(report.ok)
        self.assertNotIn('private', repr(report))

    def test_missing_measurements_never_pass(self):
        for check in [StatusIs(200), HeaderEquals('x', 'yes'), BodyContains('ok'), TimingUnder('dns', 5)]:
            with self.subTest(check=check):
                result = check.check(SimpleNamespace())
                self.assertFalse(result.ok)
                self.assertEqual(result.detail, 'not measured')

    def test_measured_values_pass_and_missing_header_fails(self):
        subject = SimpleNamespace(status=200, headers={'X-READY': 'yes'}, body='okay', timing={'dns': 5})
        self.assertTrue(evaluate(subject, [StatusIs(200), HeaderEquals('x-ready', 'yes'),
                                           BodyContains('okay'), TimingUnder('dns', 5)]).ok)
        self.assertEqual(HeaderEquals('absent', 'yes').check(subject).detail, 'failed')

    def test_strict_bounds_duplicates_and_nonfinite_timing(self):
        for checks in ([], [StatusIs(200)] * 17, [StatusIs(200)] * 2):
            with self.assertRaises(StateError):
                evaluate(SimpleNamespace(status=200), checks)
        for budget in (True, 0, -1, float('nan'), float('inf'), '5'):
            with self.assertRaises(StateError):
                TimingUnder('dns', budget)
        for measurement in (True, -1, float('nan'), float('inf'), '5', None):
            result = TimingUnder('dns', 5).check(SimpleNamespace(timing={'dns': measurement}))
            self.assertEqual(result.detail, 'not measured')
        for name in ('contains secret', 'x' * 65, '', None):
            with self.assertRaises(StateError):
                StatusIs(200, name)
        for status in (True, 99, 600, 200.0):
            with self.assertRaises(StateError):
                StatusIs(status)

    def test_mapping_refuses_excess_bad_shapes_and_names(self):
        for mapping in ({}, [], {'a': 'same', 'b': 'same'}, {'': 'ok'}, {'x': 'unsafe name'},
                        {'x' * 4097: 'ok'}, {str(i): str(i) for i in range(17)}):
            with self.assertRaises(StateError):
                condition_mapping(mapping)

    def test_pinned_condition_objects_and_omitempty(self):
        mapping = {'[STATUS] == 200': 'status'}
        result = condition_report({}, mapping)
        self.assertFalse(result.ok)
        self.assertEqual(result.results[0].detail, 'not measured')
        self.assertTrue(condition_report({'conditionResults': [
            {'condition': '[STATUS] == 200', 'success': True}]}, mapping).ok)
        for raw in (None, {}, [True], [{'condition': 'a', 'success': 1}],
                    [{'condition': 'a', 'success': True, 'body': 'secret'}],
                    [{'condition': 'a', 'success': True}] * 2,
                    [{'condition': str(i), 'success': True} for i in range(17)]):
            with self.subTest(raw=raw), self.assertRaises(StateError):
                condition_report({'conditionResults': raw}, mapping)
