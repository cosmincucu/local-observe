"""TTL readback through the real bounded client and supported ClickHouse metadata shape."""
import json
import unittest
from unittest.mock import patch

from local_observe.security.store import ClickHouseSecurityReader, SecurityEventStore
from local_observe.security.ttl import (DEFAULT_POLICY, MAX_DDL_BYTES, MAX_SQL_DEPTH, MAX_TTL_BYTES,
                                       TtlRefused, compare, table_ttl_expression)
from local_observe.store.backends.clickhouse import ClickHouse


# Synthetic fixture in ClickHouse CREATE TABLE rendering form, not a live acceptance capture.
LIVE_TTL = ("toDateTime(ts) + toIntervalDay(1825) DELETE WHERE retention_tier = 'critical', "
            "toDateTime(ts) + toIntervalDay(90) DELETE WHERE retention_tier = 'routine'")
CREATE_TABLE = """CREATE TABLE security_events.events
(
    `ts` DateTime64(9, 'UTC'),
    `retention_tier` LowCardinality(String),
    `source` LowCardinality(String),
    `event_id` String
)
ENGINE = ReplacingMergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (source, event_id)
TTL {ttl}
SETTINGS index_granularity = 8192"""


class NoopWriter:
    def execute(self, statement):
        return 'Ok.'


class Response:
    def __init__(self, row):
        self.body = json.dumps({'data': [row], 'rows': 1}).encode()

    def read(self, maximum):
        return self.body[:maximum]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class MetadataReadbackTests(unittest.TestCase):
    def store(self, metadata):
        opener = unittest.mock.Mock()

        def answer(request, timeout):
            sql = request.data.decode()
            if 'system.tables' in sql:
                # Server metadata contract, independent of the reader's mutable SQL constant.
                self.assertNotRegex(sql, r'(?i)\bttl_expression\b')
                self.assertRegex(sql, r'(?i)\bcount\(\)\s+AS\s+table_count\b')
                self.assertRegex(sql, r'(?i)\bany\(create_table_query\)\s+AS\s+create_table_query\b')
                if isinstance(metadata, Exception):
                    raise metadata
                return Response(metadata)
            return Response({'row_count': '0'})

        opener.open.side_effect = answer
        self.addCleanup(patch.stopall)
        patch('urllib.request.build_opener', return_value=opener).start()
        client = ClickHouse('https://clickhouse.invalid/', 'reader', 'test-credential')
        return SecurityEventStore(writer=NoopWriter(), reader=ClickHouseSecurityReader(client))

    def verdict(self, ddl):
        return self.store({'table_count': '1', 'create_table_query': ddl}).verify_ttl()

    def test_supported_metadata_round_trips_the_declared_policy(self):
        verdict = self.verdict(CREATE_TABLE.format(ttl=LIVE_TTL))
        self.assertEqual(verdict.status, 'match')
        self.assertEqual(verdict.comparison.live, DEFAULT_POLICY)
        self.assertEqual(verdict.expired, 0)

    def test_different_live_retention_is_drift(self):
        verdict = self.verdict(CREATE_TABLE.format(ttl=LIVE_TTL.replace('1825', '1824')))
        self.assertEqual(verdict.status, 'drift')
        self.assertIn('1824d', verdict.comparison.detail)

    def test_missing_table_and_existing_table_without_ttl_are_distinct(self):
        missing = self.store({'table_count': '0', 'create_table_query': ''}).verify_ttl()
        no_ttl = self.verdict(CREATE_TABLE.replace('TTL {ttl}\n', ''))
        self.assertEqual(missing.status, 'unreadable')
        self.assertIn('absent', missing.comparison.detail)
        self.assertEqual(no_ttl.status, 'no-ttl')

    def test_non_text_empty_or_missing_metadata_is_unreadable(self):
        for ddl in (None, 3, [], {}, '', 'CREATE TABLE broken', '\ud800'):
            with self.subTest(ddl=repr(ddl)):
                self.assertEqual(self.verdict(ddl).status, 'unreadable')
        self.assertEqual(self.store({'table_count': '1'}).verify_ttl().status, 'unreadable')

    def test_count_must_identify_exactly_one_table_or_absence(self):
        for count in (None, True, 1.0, '1.0', 2, -1, 'secret-count'):
            with self.subTest(count=count):
                verdict = self.store({'table_count': count, 'create_table_query':
                                      CREATE_TABLE.format(ttl=LIVE_TTL)}).verify_ttl()
                self.assertEqual(verdict.status, 'unreadable')
                self.assertNotIn('secret-count', verdict.comparison.detail)

    def test_unreachable_metadata_is_sanitized_for_both_public_checks(self):
        for operation in ('verify_ttl', 'ensure_schema'):
            with self.subTest(operation=operation):
                store = self.store(OSError('test-credential secret-payload'))
                result = getattr(store, operation)()
                self.assertEqual(result.comparison.status, 'unreadable')
                self.assertIn('could not be read', result.comparison.detail)
                self.assertNotIn('test-credential', result.comparison.detail)
                self.assertNotIn('secret-payload', result.comparison.detail)

    def test_oversized_transport_response_is_unreadable(self):
        verdict = self.verdict(CREATE_TABLE.format(ttl=LIVE_TTL) + ' ' * MAX_DDL_BYTES)
        self.assertEqual(verdict.status, 'unreadable')


class TableTtlExtractionTests(unittest.TestCase):
    def test_column_ttl_does_not_stand_in_for_table_ttl(self):
        ddl = ("CREATE TABLE x (`ts` DateTime, payload String TTL ts + INTERVAL 1 DAY) "
               "ENGINE = MergeTree ORDER BY ts")
        self.assertEqual(table_ttl_expression(ddl), '')
        self.assertEqual(compare(table_ttl_expression(ddl + ' TTL ' + LIVE_TTL)).status, 'match')

    def test_quoted_values_identifiers_and_comments_cannot_supply_a_table_ttl(self):
        for distractor in ("'TTL fake SETTINGS fake'", "'it\\'s TTL fake'", "'it''s TTL fake'"):
            ddl = (f"CREATE TABLE x (`TTL` String DEFAULT {distractor}, ts DateTime) "
                   "ENGINE = MergeTree ORDER BY ts /* TTL fake */ -- TTL fake\n# TTL fake\n")
            with self.subTest(distractor=distractor):
                self.assertEqual(table_ttl_expression(ddl), '')
                self.assertEqual(compare(table_ttl_expression(ddl + 'TTL ' + LIVE_TTL)).status, 'match')

    def test_settings_and_table_comment_terminate_the_ttl(self):
        for suffix in ('', ';', " COMMENT 'TTL fake SETTINGS fake'", ' SETTINGS index_granularity = 8192',
                       " SETTINGS index_granularity = 8192 COMMENT 'TTL fake'"):
            ddl = 'CREATE TABLE x (ts DateTime) ENGINE = MergeTree ORDER BY ts TTL ' + LIVE_TTL + suffix
            with self.subTest(suffix=suffix):
                self.assertEqual(compare(table_ttl_expression(ddl)).status, 'match')

    def test_malformed_ddl_is_refused_including_the_ignored_suffix(self):
        valid = CREATE_TABLE.format(ttl=LIVE_TTL)
        for ddl in (valid + ')', valid + '(', valid + " COMMENT 'unterminated", valid + ' /*',
                    valid + '; SELECT 1', valid.replace('TTL ', 'TTL TTL ', 1),
                    valid.replace(LIVE_TTL, ''), valid.replace('CREATE TABLE', 'CREATE VIEW'),
                    valid + ' /* nested /* comment */',
                    'CREATE TABLE x ENGINE = MergeTree TTL ' + LIVE_TTL):
            with self.subTest(ddl=ddl[-80:]):
                with self.assertRaises(TtlRefused):
                    table_ttl_expression(ddl)

    def test_direct_parser_bounds_cover_bytes_nesting_and_ttl_size(self):
        for ddl in (' ' * (MAX_DDL_BYTES + 1), 'é' * MAX_DDL_BYTES,
                    '(' * (MAX_SQL_DEPTH + 1) + ')' * (MAX_SQL_DEPTH + 1),
                    CREATE_TABLE.format(ttl='x' * (MAX_TTL_BYTES + 1))):
            with self.subTest(length=len(ddl)):
                with self.assertRaises(TtlRefused):
                    table_ttl_expression(ddl)


class ExactPolicyTests(unittest.TestCase):
    def test_normalized_parentheses_quoted_identifiers_and_reversed_tiers_match(self):
        clauses = ["((toDateTime(`ts`)) + (toIntervalDay(90))) DELETE WHERE (`retention_tier` = 'routine')",
                   '(toDateTime("ts") + INTERVAL 1825 DAY) delete where ("retention_tier" = \'critical\')']
        self.assertEqual(compare(', '.join(clauses)).status, 'match')

    def test_actual_clickhouse_25_12_canonical_implicit_delete(self):
        # Exact TTL bytes observed in SHOW CREATE from 25.12.5.44, not builder output.
        actual = ("toDateTime(ts) + toIntervalDay(1825) WHERE retention_tier = 'critical', "
                  "toDateTime(ts) + toIntervalDay(90) WHERE retention_tier = 'routine'")
        self.assertEqual(compare(table_ttl_expression(CREATE_TABLE.format(ttl=actual))).status, 'match')
        self.assertEqual(compare(actual.replace('toIntervalDay(90)', 'toIntervalDay(91)')).status, 'drift')
        for expression in (actual + ', toDateTime(ts) + toIntervalDay(1)',
                           actual.replace(' WHERE', ' TO DISK \'cold\' WHERE'),
                           actual.replace(' WHERE', ' RECOMPRESS CODEC(ZSTD) WHERE'),
                           actual.replace(' WHERE', ' DELETE DELETE WHERE'),
                           actual.replace("retention_tier = 'critical'", "retention_tier = 'routine'"),
                           actual.split(', ')[0]):
            with self.subTest(expression=expression):
                self.assertEqual(compare(expression).status, 'unreadable')

    def test_other_deletion_rules_cannot_hide_beside_the_two_expected_fragments(self):
        for expression in (LIVE_TTL + ', toDateTime(ts) + INTERVAL 1 DAY DELETE',
                           LIVE_TTL + ', ', ', ' + LIVE_TTL,
                           LIVE_TTL.replace('toDateTime(ts) + ', ''),
                           LIVE_TTL.replace('toDateTime(ts)', 'now()'),
                           LIVE_TTL.replace('toDateTime(ts)', 'toDateTime(received_at)'),
                           LIVE_TTL.replace("= 'critical'", "= 'critical' OR 1"),
                           LIVE_TTL.replace('DELETE WHERE', 'TO VOLUME \'archive\' DELETE WHERE'),
                           LIVE_TTL.replace('toIntervalDay(1825)', 'toIntervalDay(1825) * 0'),
                           LIVE_TTL.replace('toIntervalDay(1825)', 'toIntervalDay(1825) + toIntervalDay(1)'),
                           LIVE_TTL.replace('toIntervalDay(1825)', 'toIntervalHour(1825)'),
                           LIVE_TTL.replace("'critical'", "'CRITICAL'"),
                           LIVE_TTL.replace('retention_tier', 'Retention_tier'),
                           LIVE_TTL + ' SETTINGS index_granularity = 8192'):
            with self.subTest(expression=expression[:90]):
                self.assertEqual(compare(expression).status, 'unreadable')

    def test_an_oversized_day_count_is_unreadable_without_numeric_conversion(self):
        self.assertEqual(compare(LIVE_TTL.replace('1825', '1' * 5000)).status, 'unreadable')

    def test_a_policy_written_only_inside_a_comment_does_not_match(self):
        self.assertFalse(compare('/* ' + LIVE_TTL + ' */').matches)


if __name__ == '__main__':
    unittest.main()
