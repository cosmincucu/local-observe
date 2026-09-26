import copy
import unittest

from local_observe.deployment.content import Conflict
from local_observe.deployment.live import dashboard_identities


class DashboardIdentityTests(unittest.TestCase):
    def setUp(self):
        self.origin = 'https://observe.example.test'
        self.rows = [{'id': 'user.tile-one', 'href': 'https://other.example.test'},
                     {'id': 'user.dashboard-one', 'legacy_source': 'one.json', 'backend_id': None,
                      'href': self.origin+'/dashboard/backend-123'}]

    def test_ids_come_from_existing_links_not_titles(self):
        self.assertEqual(dashboard_identities(self.rows, self.origin), {'user.dashboard-one': 'backend-123'})

    def test_ambiguous_missing_or_foreign_identity_refused(self):
        bads = [self.rows + [self.rows[1]], self.rows[:1]]
        for update in ({'href': 'https://other.example.test/dashboard/backend-123'},
                       {'href': self.origin+'/dashboard/backend-123?token=secret'},
                       {'backend_id': 'different'}, {'href': self.origin+'/dashboard/../mutate'}):
            rows = copy.deepcopy(self.rows)
            rows[1].update(update)
            bads.append(rows)
        for rows in bads:
            with self.assertRaises(Conflict):
                dashboard_identities(rows, self.origin)
