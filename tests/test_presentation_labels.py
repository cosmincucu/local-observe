import unittest

from local_observe.platform.presentation import describe, text


class PresentationLabelTests(unittest.TestCase):
    def test_opaque_identifiers_are_not_human_labels(self):
        for value in ('14ff50a8-cb81-4b20-be23-c5b67e900af6',
                      '14ff50a8cb814b20be23c5b67e900af6',
                      '{14ff50a8-cb81-4b20-be23-c5b67e900af6}', None, ''):
            with self.subTest(value=value):
                self.assertEqual(text(value, 'Unnamed resource'), 'Unnamed resource')

    def test_describe_refuses_uuid_rule_label_without_changing_event(self):
        opaque = '14ff50a8-cb81-4b20-be23-c5b67e900af6'
        event = {'rule_id': opaque, 'kind': 'availability', 'resource_id': None}
        display = describe(event, config={'rule_names': {opaque: opaque}})
        self.assertEqual(display['description'], 'Monitoring incident')
        self.assertNotIn(opaque, str(display))
        self.assertEqual(event['rule_id'], opaque)

    def test_useful_labels_remain_readable_and_bounded(self):
        self.assertEqual(text('  Backup\n service  ', 'Unknown'), 'Backup service')
        self.assertEqual(text('Host 42', 'Unknown'), 'Host 42')
        self.assertEqual(len(text('x' * 200, 'Unknown')), 160)
