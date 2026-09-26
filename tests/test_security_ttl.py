"""The TTL module's own rules, and the promise that the DDL cannot disagree with them (security store).

Two claims carry this card's retention value, and both are checked here rather than asserted in a
document: the numbers exist in exactly one module, and a table cannot be *built* with a policy other
than that module's. The second is the one that catches a real defect class — a hand-ALTER, or a
merged policy change nobody applied — because it is proven by rendering the DDL and reading it back
through the same parser that reads TTLs from ``system.tables.create_table_query``.
"""
import datetime as dt
from pathlib import Path
import unittest

from local_observe.platform.vocabulary import ADMITTED_SEVERITIES
from local_observe.security import schema, ttl
from local_observe.security.ttl import (COMPARISON_STATUSES, CRITICAL_TTL_DAYS, DEFAULT_POLICY,
                                       RETENTION_CONTRAST_WITH_D9, ROUTINE_TTL_DAYS, TIERS,
                                       TIER_BY_SEVERITY, TIER_CRITICAL, TIER_ROUTINE, RetentionPolicy,
                                       TtlComparison, TtlRefused, build_ttl_clause, compare, deadline,
                                       parse_ttl_expression, tier_for)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'local_observe' / 'security'

# Product telemetry defaults, kept separate from the security-event tier policy.
D9_TELEMETRY_DAYS = {'traces': 7, 'metrics': 30, 'logs': 14}


def source(name: str) -> str:
    """One module's text, read from the package this test guards."""
    return (PACKAGE / name).read_text(encoding='utf-8')


class PolicyNumbersTests(unittest.TestCase):
    """The two numbers, stated once, and the invariant that orders them."""

    def test_the_two_numbers_are_the_ones_the_brief_ships(self):
        self.assertEqual((CRITICAL_TTL_DAYS, ROUTINE_TTL_DAYS), (1825, 90))
        self.assertEqual(DEFAULT_POLICY, RetentionPolicy())
        self.assertEqual(DEFAULT_POLICY.as_dict(), {TIER_CRITICAL: 1825, TIER_ROUTINE: 90})

    def test_critical_must_outlive_routine(self):
        """The ordering is load-bearing: a routine tier longer than critical retains *more* ordinary rows."""
        with self.assertRaises(TtlRefused):
            RetentionPolicy(critical_days=30, routine_days=90)
        self.assertEqual(RetentionPolicy(critical_days=90, routine_days=90).days(TIER_ROUTINE), 90)

    def test_a_non_whole_day_or_a_zero_is_refused(self):
        for days in (0, -1, True, False, 1.5, '90', None):
            with self.subTest(days=days):
                with self.assertRaises(TtlRefused):
                    RetentionPolicy(critical_days=days, routine_days=7)

    def test_days_is_the_only_unit_a_policy_can_be_asked_for(self):
        self.assertEqual(DEFAULT_POLICY.days(TIER_CRITICAL), 1825)
        with self.assertRaises(TtlRefused):
            DEFAULT_POLICY.days('median')

    def test_the_tier_vocabulary_is_two_names(self):
        self.assertEqual(TIERS, (TIER_CRITICAL, TIER_ROUTINE))


class DdlRenderedFromPolicyTests(unittest.TestCase):
    """The required "the test that fails if the DDL disagrees" — the DDL is an output, not a source."""

    def test_the_create_statement_carries_exactly_the_clause_the_policy_builds(self):
        for policy in (DEFAULT_POLICY, RetentionPolicy(critical_days=730, routine_days=14)):
            with self.subTest(policy=policy.as_dict()):
                ddl = schema.create_table_sql(policy)
                self.assertIn(build_ttl_clause(policy), ddl)
                self.assertEqual(parse_ttl_expression(ttl_from(ddl)), policy)

    def test_a_number_hard_coded_into_the_template_would_read_as_drift(self):
        """The failure this renders visible: somebody edits the DDL's days without editing the policy."""
        altered = schema.create_table_sql().replace('INTERVAL 1825 DAY', 'INTERVAL 1824 DAY')
        verdict = compare(ttl_from(altered))
        self.assertEqual(verdict.status, 'drift')
        self.assertIn('1824', verdict.detail)
        self.assertIn('1825', verdict.detail)

    def test_rendering_is_deterministic_and_carries_no_placeholder(self):
        self.assertEqual(schema.create_table_sql(), schema.create_table_sql(DEFAULT_POLICY))
        self.assertNotIn('{', schema.create_table_sql())

    def test_the_owned_table_is_a_replacing_keyed_on_the_event_identity(self):
        """The dedupe identity is declared, not implied: ORDER BY is the (source, event_id) pair."""
        ddl = schema.create_table_sql()
        self.assertIn('ENGINE = ReplacingMergeTree', ddl)
        self.assertIn('ORDER BY (source, event_id)', ddl)
        self.assertIn('IF NOT EXISTS', schema.ddl_statements()[0])

    def test_every_column_the_ddl_declares_is_a_column_the_writer_names(self):
        from local_observe.security.store import SecurityEvent
        row = SecurityEvent(ts='2026-09-09T00:00:00+00:00', source='sigma-stage', event_id='e' * 16,
                            rule_id='sigma.x', rule_version='1', kind='security', status='firing',
                            severity='warning', window_start='2026-09-09T00:00:00+00:00',
                            window_end='2026-09-09T00:01:00+00:00',
                            observed_at='2026-09-09T00:00:30+00:00').as_row(received_at='2026-09-09T00:01:00+00:00')
        self.assertEqual(list(row), list(schema.COLUMN_NAMES))


class ParseLiveExpressionTests(unittest.TestCase):
    """Reading a live table's TTL back, including the shapes that must be refused, not guessed."""

    LIVE = ("(toDateTime(ts) + toIntervalDay(1825)) DELETE WHERE retention_tier = 'critical', "
            "(toDateTime(ts) + toIntervalDay(90)) DELETE WHERE retention_tier = 'routine'")

    def test_clickhouses_rendered_form_parses_to_the_shipped_policy(self):
        self.assertEqual(parse_ttl_expression(self.LIVE), DEFAULT_POLICY)

    def test_tiers_are_read_by_guard_and_not_by_position(self):
        swapped = ("toDateTime(ts) + toIntervalDay(90) DELETE WHERE retention_tier = 'routine', "
                   "toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical'")
        self.assertEqual(parse_ttl_expression(swapped), DEFAULT_POLICY)

    def test_the_ddl_spelling_and_the_server_spelling_agree(self):
        self.assertEqual(parse_ttl_expression(ttl_from(schema.create_table_sql())),
                         parse_ttl_expression(self.LIVE))

    def test_no_expression_is_no_ttl_and_not_a_zero_day_policy(self):
        self.assertIsNone(parse_ttl_expression(''))
        self.assertIsNone(parse_ttl_expression('   '))

    def test_a_hand_altered_guard_column_is_refused_not_read_as_agreement(self):
        """v0.1 spelled the tier `data_class`; a table still wearing that guard is not this policy."""
        stale = ("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE data_class = 'critical', "
                 "toDateTime(ts) + toIntervalDay(90) DELETE WHERE data_class = 'routine'")
        with self.assertRaises(TtlRefused):
            parse_ttl_expression(stale)

    def test_a_missing_tier_is_refused(self):
        with self.assertRaises(TtlRefused) as context:
            parse_ttl_expression("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical'")
        self.assertIn('routine', str(context.exception))

    def test_a_tier_declared_twice_is_refused(self):
        doubled = ("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical', "
                   "toDateTime(ts) + toIntervalDay(30) DELETE WHERE retention_tier = 'critical', "
                   "toDateTime(ts) + toIntervalDay(90) DELETE WHERE retention_tier = 'routine'")
        with self.assertRaises(TtlRefused):
            parse_ttl_expression(doubled)

    def test_an_unknown_tier_name_is_refused(self):
        with self.assertRaises(TtlRefused):
            parse_ttl_expression("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'forever', "
                                 "toDateTime(ts) + toIntervalDay(90) DELETE WHERE retention_tier = 'routine'")

    def test_non_text_is_refused(self):
        for value in (None, 0, ['a']):
            with self.subTest(value=value):
                with self.assertRaises(TtlRefused):
                    parse_ttl_expression(value)


class CompareTests(unittest.TestCase):
    """The four answers the scheduled check may give, and the words it must never invent."""

    def test_every_status_in_the_vocabulary_is_reachable(self):
        cases = {'match': ttl_from(schema.create_table_sql()),
                 'drift': "toDateTime(ts) + toIntervalDay(900) DELETE WHERE retention_tier = 'critical', "
                          "toDateTime(ts) + toIntervalDay(90) DELETE WHERE retention_tier = 'routine'",
                 'no-ttl': '',
                 'unreadable': "toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical'"}
        self.assertEqual(set(cases), set(COMPARISON_STATUSES))
        for status, expression in cases.items():
            with self.subTest(status=status):
                self.assertEqual(compare(expression).status, status)

    def test_a_drift_line_names_both_numbers_and_tiers(self):
        verdict = compare("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical', "
                          "toDateTime(ts) + toIntervalDay(30) DELETE WHERE retention_tier = 'routine'")
        self.assertEqual(verdict.status, 'drift')
        self.assertIn('routine: declared 90d but the live table keeps 30d', verdict.detail)
        self.assertNotIn('critical:', verdict.detail)

    def test_no_ttl_says_nothing_is_expiring(self):
        verdict = compare('')
        self.assertIsNone(verdict.live)
        self.assertIn('no TTL clause at all', verdict.detail)
        self.assertFalse(verdict.matches)

    def test_an_unreadable_expression_names_the_rule_not_a_traceback(self):
        verdict = compare('TTL nonsense')
        self.assertEqual(verdict.status, 'unreadable')
        self.assertIn('guarded day deletions', verdict.detail)

    def test_a_verdict_word_outside_the_vocabulary_is_refused(self):
        with self.assertRaises(TtlRefused):
            TtlComparison(status='probably-fine', declared=DEFAULT_POLICY, live=DEFAULT_POLICY, detail='x')

    def test_the_verdict_is_json_safe(self):
        payload = compare('nope').as_dict()
        self.assertEqual(set(payload), {'status', 'declared', 'live', 'detail'})


class TierSelectionTests(unittest.TestCase):
    """Which row gets kept for years, decided by the policy and by nobody else."""

    def test_every_severity_intake_admits_selects_a_tier(self):
        self.assertEqual(sorted(TIER_BY_SEVERITY), sorted(ADMITTED_SEVERITIES))
        self.assertEqual(tier_for('critical'), TIER_CRITICAL)
        for severity in ('warning', 'info'):
            with self.subTest(severity=severity):
                self.assertEqual(tier_for(severity), TIER_ROUTINE)

    def test_a_severity_outside_the_vocabulary_is_refused_rather_than_defaulted(self):
        """Defaulting to `routine` would silently shorten a row somebody meant to keep for years."""
        for word in ('error', 'unknown', '', None):
            with self.subTest(word=word):
                with self.assertRaises(TtlRefused):
                    tier_for(word)


class DeadlineTests(unittest.TestCase):
    """The one piece of date arithmetic here, pinned so a tier length is never an opinion."""

    def test_the_deadline_is_the_stamp_plus_the_tier_in_whole_days(self):
        stamp = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(deadline(TIER_CRITICAL, stamp), stamp + dt.timedelta(days=1825))
        self.assertEqual(deadline(TIER_ROUTINE, stamp), stamp + dt.timedelta(days=90))

    def test_a_naive_instant_is_refused_because_the_host_zone_would_decide_it(self):
        with self.assertRaises(TtlRefused):
            deadline(TIER_ROUTINE, dt.datetime(2026, 9, 9, 12, 0))


class SinglePlaceTests(unittest.TestCase):
    """The "one place" claim, checked against the tree rather than against a comment."""

    def test_the_numbers_appear_in_no_other_module_of_the_package(self):
        for name in ('schema.py', 'store.py', 'dualwrite.py', 'backup.py', 'cli.py', '__init__.py'):
            text = source(name)
            with self.subTest(module=name):
                self.assertNotIn('1825', text)
                self.assertNotIn('DELETE WHERE retention_tier', text)

    def test_only_this_module_writes_a_ttl_clause_at_all(self):
        """`schema.py` builds its clause by calling `ttl.build_ttl_clause`; it does not spell one."""
        self.assertIn('DELETE WHERE retention_tier', source('ttl.py'))
        self.assertIn('build_ttl_clause(', source('schema.py'))
        self.assertNotIn('DELETE WHERE retention_tier', source('schema.py'))

    def test_the_package_never_alters_a_table(self):
        """Reported drift is an operator's `ALTER`; a checker that fixes the store is not a checker."""
        for name in ('ttl.py', 'schema.py', 'store.py', 'dualwrite.py', 'memory.py', 'cli.py'):
            with self.subTest(module=name):
                self.assertNotIn('ALTER TABLE', source(name))
                self.assertNotIn('TRUNCATE', source(name))

    def test_this_ttl_is_not_d9s_telemetry_retention(self):
        """Telemetry defaults must not replace the longer security-event tier policy."""
        self.assertNotIn(DEFAULT_POLICY.critical_days, D9_TELEMETRY_DAYS.values())
        line = RETENTION_CONTRAST_WITH_D9
        for marker in ('Security-event retention', 'telemetry retention', 'traces', 'store/retention.py'):
            self.assertIn(marker, line)
        self.assertIn('RETENTION_CONTRAST_WITH_D9', source('ttl.py'))
        for name in ('ttl.py', 'schema.py', 'store.py'):
            with self.subTest(module=name):
                for signal in D9_TELEMETRY_DAYS:
                    self.assertNotIn(f"= '{signal}'", source(name),
                                     f'{name} tiers on a telemetry signal; that retention is store/retention.py')


def ttl_from(ddl: str) -> str:
    """The TTL body inside DDL this repository rendered, in the spelling `parse` accepts."""
    return schema.ttl_from_ddl(ddl)


if __name__ == '__main__':
    unittest.main()
