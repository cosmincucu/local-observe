"""The Dagu execution path: one dispatch, never a redispatch.

job observe standard (decision job observation) retired the *observation* half that used to live in this file -- the named-unit
`busctl` sampler and its nine-state classifier now live in `archive/platform-jobs/`, replaced by
`systemd_exporter` and Healthchecks (`components/control/job-observe/`). What stays here is the half
job observation left standing: `jobs` in `docs/COMPONENTS.md` is Dagu plus the scoped SSH adapter, and the claim
this file pins is that a lost start acknowledgement is reconciled by query, never by dispatching the
work a second time. The witness tests moved to `tests/test_deadman.py`.
"""
import tempfile
import unittest
import uuid
from pathlib import Path

from local_observe.http import TransportError
from local_observe.platform import dagu


class Platform:
    def __init__(self):
        self.claims = 0
        self.claim = {'status': 'executing', 'execution_id': str(uuid.uuid4()), 'runner_token': 'synthetic',
                      'request': {'action': 'inspect', 'version': '1', 'targets': ['fixture'], 'parameters': {}}}

    def request(self, method, path, payload):
        if path.endswith('/claim'):
            self.claims += 1
            return 200, self.claim
        return 200, {'status': payload['outcome']}


class Dagu:
    def __init__(self):
        self.starts = 0
        self.run_id = None
        self.result = 'running'
        self.lost_ack = False

    def request(self, method, path, payload=None):
        if path.endswith('/spec'):
            return 200, {'spec': 'fixture'}
        if path.endswith('/start'):
            self.starts += 1
            self.run_id = payload['dagRunId']
            if self.lost_ack:
                raise TransportError('Lost start acknowledgement')
            return 200, {'dagRunId': self.run_id}
        return 200, {'dagRunDetails': {'name': 'inspect', 'dagRunId': self.run_id, 'statusLabel': self.result}}


class DaguTests(unittest.TestCase):
    def test_restart_and_lost_ack_never_redispatch(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'journal.json'
            platform, engine = Platform(), Dagu()
            binding = {'action': 'inspect', 'version': '1', 'targets': ['fixture'], 'dag': 'inspect',
                       'sha256': hashlib.sha256(b'fixture').hexdigest()}
            action = str(uuid.uuid4())
            engine.lost_ack = True
            self.assertEqual(dagu.execute(platform, engine, action, binding, path)['status'], 'executing')
            engine.result = 'succeeded'
            self.assertEqual(dagu.execute(platform, engine, action, binding, path)['status'], 'succeeded')
            self.assertEqual(dagu.execute(platform, engine, action, binding, path)['status'], 'succeeded')
            self.assertEqual((engine.starts, platform.claims), (1, 1))

    def test_changed_spec_cannot_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            platform = Platform()
            with self.assertRaises(ValueError):
                dagu.execute(platform, Dagu(), str(uuid.uuid4()), {'dag': 'inspect', 'sha256': 'bad'},
                             Path(directory) / 'journal.json')
            self.assertEqual(platform.claims, 0)


if __name__ == '__main__':
    unittest.main()
