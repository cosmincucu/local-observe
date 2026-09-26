"""The provider boundary: what a source may reach, how silence ages, and what undeclared becomes.

Four proofs live here. (1) A provider module cannot reach a declaration writer, checked by reading
its syntax tree, with a positive control showing the check bites. (2) A provider's public surface is
`observe` and `snapshot` and nothing else, and no constructor accepts a write target. (3) What a
source stops seeing is aged with `observed_at` evidence, and every case where absence is not
provable — stale, partial, failed, never-seen — returns a status instead of a list of gone resources
(the "stale discovery is not reported as absence" row of docs/COMPONENTS.md section 5). (4) An
undeclared observation still ends as one review pull request and touches nothing else.

Every case reads the tick's own state directory through `proposal_documents`, never through a bare
`glob('*.json') + next()`: one tick leaves two `*.json` documents in `state/proposals` (the proposal
and the forge receipt beside it) and `readdir` order is not a fact a test may rely on. See hermetic discovery test.
"""
import ast
import base64
import copy
import datetime as dt
import inspect
import json
from collections.abc import Iterable
from pathlib import Path
import re
import tempfile
import types
import unittest
from unittest.mock import patch

from local_observe.inventory import (discovery, docker_provider, index, kube_provider,
                                     sweep_provider, validation, worker)
from local_observe.inventory.validation import InvalidInventory, digest, read_document, timestamp, utc_text

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
PROVIDER_FILES = ('docker_provider.py', 'sweep_provider.py', 'kube_provider.py')
# A provider that imports one of these has picked up a write path or a decision it does not own:
# index writes declarations, forge opens pull requests, worker schedules, api and cli serve.
WRITER_MODULES = {'index', 'forge', 'worker', 'api', 'cli', 'main', 'state'}
# Names that write, decide or resolve. `discovery` stays importable for the `Observation` type, so
# the rule bites on the verbs: a provider may hold the data type and may not call these.
WRITER_VERBS = {'upsert', 'declare', 'declared', 'build', 'publish', 'propose', 'ingest', 'drift',
                'ageing', 'mark_decommissioned', 'delete', 'remove', 'drop', 'resolve', 'save',
                'open', 'write_text', 'write_bytes', 'unlink', 'mkdir', 'rename', 'replace', 'commit'}
# Modules that could reach a network or another process. Tolerated in docker_provider, which reads
# the socket an operator named; refused in the sources that must only read what was injected.
SCAN_MODULES = {'subprocess', 'socket', 'ssl', 'asyncio', 'select', 'ctypes', 'urllib', 'http', 'requests',
                'smtplib', 'ftplib', 'telnetlib', 'multiprocessing', 'threading', 'os'}
# What `worker.tick` hangs off a proposal path to store the forge receipt that answers it, so one
# `*.json` glob in `state/proposals` matches both the proposal and the receipt. See proposal_documents.
RECEIPT_SUFFIX = '.result.json'
SQL_SHAPE = re.compile(r'\b(INSERT INTO|DELETE FROM|DROP TABLE|UPDATE \w+ SET|REPLACE INTO)\b')
CIDR_SHAPE = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}')
Q5 = '10.11.0.0/16'


def boundary_findings(source: str, *, scan_capable: bool) -> list[str]:
    """Return every way this provider source tries to write, decide, or scan."""
    findings = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names, line = {alias.name.split('.')[0] for alias in node.names}, node.lineno
            for name in names:
                if name in WRITER_MODULES or name in WRITER_VERBS or (scan_capable and name in SCAN_MODULES):
                    findings.add(f'line {line}: imports {name}')
        elif isinstance(node, ast.ImportFrom):
            line = node.lineno
            modules = ({(node.module or '').split('.')[-1]} if node.module else set()) | {
                alias.name.split('.')[0] for alias in node.names}
            for name in modules - {''}:
                if name in WRITER_MODULES or name in WRITER_VERBS or (scan_capable and name in SCAN_MODULES):
                    findings.add(f'line {line}: imports {name}')
        elif isinstance(node, ast.Attribute):
            if node.attr in WRITER_VERBS:
                findings.add(f'line {node.lineno}: reaches {node.attr}')
        elif isinstance(node, ast.Name) and node.id in WRITER_VERBS:
            findings.add(f'line {node.lineno}: calls {node.id}')
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and SQL_SHAPE.search(node.value):
            findings.add(f'line {node.lineno}: carries a SQL statement')
    return sorted(findings)


def no_probe(address: str) -> bool:
    """A prober that answers nothing: construction must never probe by itself."""
    return False


def answers_only(*addresses):
    """Build a prober closure answering True for exactly the addresses given."""
    answering = set(addresses)
    return lambda address: address in answering


def build_index(root: Path) -> Path:
    """Build the declared index every case below reads, from the committed example."""
    path = root/'inventory.db'
    index.build(read_document(ROOT/'examples/inventory/declared.yaml'), path, 'fixture-v1', now=NOW)
    return path


def base_config(root: Path, index_path: Path) -> dict:
    return {'state': str(root/'state'), 'index': str(index_path)}


def proposal_documents(paths: Iterable[Path]) -> list[Path]:
    """Pick the durable proposals out of a `state/proposals` listing, in name order.

    One tick leaves two kinds of `*.json` in that directory: the proposal `<key>.json` (whose
    `status` is `needs_review`) and the forge receipt `<key>.result.json` answering it (whose
    `status` is `created`). `Path.glob` yields them in whatever order `readdir` returned, which no
    filesystem promises and which differed between the two runs of the `deterministic-tests` job on
    2026-09-08 (the first run listed the proposal, the second listed the receipt). Reading by name -
    filter the receipt suffix, then sort - depends on what the two files are called, not on the
    order the directory happened to be walked in.
    """
    return sorted(path for path in paths if not path.name.endswith(RECEIPT_SUFFIX))


def sweep_of(*addresses, source='sweep-demo', now=NOW) -> sweep_provider.SweepProvider:
    """A sweep whose plan is exactly these host addresses, so tests never depend on range arithmetic."""
    return sweep_provider.SweepProvider(source=source, cidrs=[address + '/32' for address in addresses],
                                       sweep_allowlist=[Q5], prober=answers_only(*addresses), now=now)


def kube_of(items, *, source='kube-demo', now=NOW) -> kube_provider.KubeProvider:
    return kube_provider.KubeProvider(source=source, listing={'items': list(items)}, now=now)


def demo_docker(*, source='demo-docker', now=NOW) -> docker_provider.DockerProvider:
    return docker_provider.DockerProvider(['demo'], source=source, socket='/run/user/1001/docker.sock',
                                         expected_root='/stage/docker', now=now)


def colliding_pod() -> dict:
    """A pod named demo-api in namespace demo holding the address probe-1 was declared with.

    Both halves are real declarations in examples/inventory/declared.yaml: the service alias belongs
    to demo-api and the address belongs to host probe-1, so this one observation matches two
    resources and nothing may decide between them.
    """
    return {'metadata': {'name': 'demo-api', 'namespace': 'demo', 'uid': 'bbbbbbbb-1111-4111-8111-111111111111'},
            'spec': {'containers': [{'image': 'registry.example.invalid/api:2'}]},
            'status': {'phase': 'Running', 'podIP': '10.11.0.21'}}


def docker_cli(rows):
    """A `docker` CLI stand-in answering info, ps and inspect for the five allowlisted fields."""

    def run(args, **kwargs):
        if args[1] == 'info':
            body = {'DockerRootDir': '/stage/docker', 'SecurityOptions': ['name=rootless']}
        elif args[1] == 'ps':
            return types.SimpleNamespace(returncode=0, stdout='\n'.join(row['id'] for row in rows))
        else:
            row = next(item for item in rows if item['id'] == args[-1])
            body = {'id': row['id'], 'state': row.get('state', 'running'), 'project': 'demo',
                    'service': row['service'], 'resource_id': row.get('resource_id', '')}
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(body))
    return run


class FakeForge:
    """A Gitea stand-in that records calls: enough of the branches/contents/pulls API for publish()."""

    def __init__(self):
        self.branch = None
        self.pulls: list[dict] = []
        self.calls: list[tuple] = []
        self.contents: dict[str, dict] = {}

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == 'GET' and '/pulls?' in path:
            return 200, self.pulls
        if method == 'GET' and '/branches/' in path:
            if path.endswith('/main') or self.branch:
                return 200, {'commit': {'id': 'base-commit'}}
            return 404, None
        if method == 'POST' and path.endswith('/branches'):
            self.branch = payload['new_branch_name']
            return 201, {'commit': {'id': 'new-commit'}}
        if method == 'GET' and '/contents/' in path:
            return 404, None
        if method == 'POST' and '/contents/' in path:
            self.contents[path] = json.loads(base64.b64decode(payload['content']).decode())
            return 201, {}
        if method == 'POST' and path.endswith('/pulls'):
            pull = {'number': len(self.pulls) + 1, 'html_url': 'https://forge.example.invalid/1',
                    'body': payload['body'], 'head': {'ref': payload['head']}, 'base': {'ref': payload['base']}}
            self.pulls.append(pull)
            return 201, pull
        raise AssertionError((method, path))


def forge_client(fake):
    """Wrap a fake in the client interface so `worker.tick` drives the real forge.publish path."""
    from local_observe.http import JsonClient

    class Client(JsonClient):
        def __init__(self):
            pass

        def request(self, method, path, payload=None):
            return fake.request(method, path, payload)
    return Client()


class ProviderSurfaceTests(unittest.TestCase):
    """The interface is the boundary: two verbs, and no argument that names something to write to."""

    def providers(self):
        return {docker_provider.DockerProvider.__name__: demo_docker(),
                sweep_provider.SweepProvider.__name__: sweep_of('10.11.0.20'),
                kube_provider.KubeProvider.__name__: kube_of([])}

    def test_each_provider_exposes_only_observe_and_snapshot(self):
        for name, instance in self.providers().items():
            with self.subTest(provider=name):
                public = {attribute for attribute, value in vars(type(instance)).items()
                          if not attribute.startswith('_') and callable(value)}
                self.assertEqual(public, {'observe', 'snapshot'},
                                 'a third verb would be a capability the plan did not grant')

    def test_the_protocol_declares_the_same_two_verbs(self):
        surface = {name for name, value in vars(discovery.Provider).items() if not name.startswith('_')}
        self.assertEqual(surface, {'observe', 'snapshot'})

    def test_no_constructor_accepts_a_write_target(self):
        forbidden = {'index', 'db', 'database', 'path', 'output', 'client', 'connection', 'forge',
                     'repository', 'document', 'proposal', 'target', 'transaction', 'cursor'}
        for name, instance in self.providers().items():
            with self.subTest(provider=name):
                names = set(inspect.signature(type(instance).__init__).parameters) - {'self'}
                self.assertEqual(names & forbidden, set())

    def test_each_provider_satisfies_the_protocol_structurally(self):
        for name, instance in self.providers().items():
            with self.subTest(provider=name):
                self.assertIsInstance(instance, discovery.Provider)

    def test_constructing_a_provider_probes_nothing(self):
        self.assertTrue(hasattr(sweep_of('10.11.0.20'), 'observe'))
        probe_seen = []
        sweep_provider.SweepProvider(source='sweep-demo', cidrs=['10.11.0.20/32'], sweep_allowlist=[Q5],
                                    prober=probe_seen.append, now=NOW)
        self.assertEqual(probe_seen, [])


class ProviderCannotWriteDeclarationsTests(unittest.TestCase):
    """Task 5's mechanism: read the syntax tree of each provider, then prove the reader is not blind."""

    def test_no_provider_module_reaches_a_declaration_writer(self):
        for name in PROVIDER_FILES:
            with self.subTest(provider=name):
                text = (ROOT/'local_observe/inventory'/name).read_text(encoding='utf-8')
                self.assertEqual(boundary_findings(text, scan_capable=name != 'docker_provider.py'), [],
                                 f'{name} must return observations and hold no write path')

    def test_the_check_bites_on_a_source_that_does_write(self):
        """A guard that cannot fail is not a guard: the same reader, pointed at a bad file."""
        bad = ('from .index import build\nimport subprocess\nimport socket\n\n'
               'def go(document, output):\n'
               '    build(document, output)\n'
               "    output.write_text('INSERT INTO resources VALUES (1)')\n"
               "    socket.socket().connect(('10.11.0.1', 1))\n"
               "    subprocess.run(['nmap', '10.11.0.0/24'])\n")
        findings = boundary_findings(bad, scan_capable=True)
        self.assertEqual(len(findings), 7, findings)
        self.assertTrue(any('imports index' in item for item in findings), findings)
        self.assertTrue(any('imports build' in item for item in findings), findings)
        self.assertTrue(any('calls build' in item for item in findings), findings)
        self.assertTrue(any('reaches write_text' in item for item in findings), findings)
        self.assertTrue(any('SQL' in item for item in findings), findings)
        self.assertTrue(any('imports subprocess' in item for item in findings), findings)
        quiet = boundary_findings(bad, scan_capable=False)
        self.assertEqual([item for item in quiet if 'socket' in item or 'subprocess' in item], [],
                         'the scan-capable rule must be the only difference between the two reads')
        self.assertEqual(len(quiet), 5, quiet)

    def test_only_the_rfc1918_boundaries_are_committed_in_a_provider_module(self):
        allowed = {str(network) for network in sweep_provider.RFC1918}
        for name in PROVIDER_FILES:
            with self.subTest(provider=name):
                text = (ROOT/'local_observe/inventory'/name).read_text(encoding='utf-8')
                self.assertEqual(set(CIDR_SHAPE.findall(text)) - allowed, set(),
                                 'a real range is operator configuration, never a shipped literal')

    def test_a_provider_run_reaches_no_writer_even_when_its_output_is_undeclared(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = build_index(root)
            config = base_config(root, index_path)
            before = index_path.read_bytes()

            def boom(*args, **kwargs):
                raise AssertionError('a declaration writer was reached')

            pod = {'metadata': {'name': 'solo-7d9-a1b2c', 'namespace': 'demo',
                               'uid': 'aaaaaaaa-1111-4111-8111-111111111111'},
                   'spec': {'containers': [{'image': 'registry.example.invalid/x:1'}]},
                   'status': {'phase': 'Running', 'podIP': '10.11.0.6'}}
            with patch.object(worker, 'publish', boom), patch.object(discovery, 'propose', boom), \
                    patch.object(index, 'build', boom), patch.object(validation, 'declared', boom):
                states = [worker.tick(config, sweep_of('10.11.0.5'), now=NOW),
                          worker.tick({**config, 'state': str(root/'state-b')}, kube_of([pod]), now=NOW)]
                with patch('local_observe.inventory.docker_provider.subprocess.run',
                           side_effect=docker_cli([{'id': 'a' * 64, 'service': 'api'}])):
                    states.append(worker.tick({**config, 'state': str(root/'state-c')}, demo_docker(), now=NOW))
            for state in states:
                self.assertEqual(state['proposals'], [], 'nothing was allowlisted, so no review may open')
                self.assertGreater(state['observations'], 0)
            self.assertEqual(index_path.read_bytes(), before, 'a provider run must not touch declarations')
            report = json.loads((root/'state'/'drift.json').read_text())
            self.assertIn('undeclared', {item['kind'] for item in report['findings']})
            self.assertEqual(list((root/'state'/'proposals').glob('*.json')), [])


class UndeclaredBecomesOnePullRequestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = build_index(self.root)
        self.declared = read_document(ROOT/'examples/inventory/declared.yaml')

    def test_a_swept_host_never_declared_opens_one_pr_and_changes_no_declaration(self):
        # 10.11.0.21 is declared as probe-1, so it resolves and must stay silent; .222 is new.
        provider = sweep_of('10.11.0.21', '10.11.0.222')
        config = {**base_config(self.root, self.index_path),
                  'proposal_allowlist': [digest(['network-sweep', '10.11.0.222'])],
                  'forge': {'repository': 'owner/inventory', 'branch': 'main', 'path': 'inventory/declared.yaml'},
                  'ageing_grace_seconds': 900}
        before = self.index_path.read_bytes()
        forge = FakeForge()
        first = worker.tick(config, provider, client=forge_client(forge), now=NOW)
        self.assertEqual([item['status'] for item in first['proposals']], ['created'])
        self.assertEqual(len(forge.pulls), 1)
        self.assertTrue(first['proposals'][0]['branch'].startswith('local-observe/discovery/'),
                        'the write lands on a review branch, never the base branch')
        self.assertEqual(first['ageing'], 'evaluated', 'a complete sweep may age; here nothing was silent')
        self.assertEqual(first['aged_out'], 0)
        self.assertTrue((self.root/'state'/'ageing.json').is_file())
        self.assertEqual(self.index_path.read_bytes(), before, 'the served declaration index is byte-identical')
        proposals = proposal_documents((self.root/'state'/'proposals').glob('*.json'))
        self.assertEqual(len(proposals), 1, 'one proposal document; the forge receipt is not a proposal')
        proposal = json.loads(proposals[0].read_text())
        self.assertEqual(proposal['status'], 'needs_review')
        declared_ids = {item['id'] for item in self.declared['resources']}
        self.assertNotIn(proposal['resource']['id'], declared_ids, 'the proposal mints a fresh UUID')
        published = list(forge.contents.values())[0]
        self.assertEqual([item['id'] for item in published['resources']], [proposal['resource']['id']],
                         'the review branch carries the one proposed resource and nothing else')

        later = NOW + dt.timedelta(minutes=15)
        quiet = FakeForge()
        second = worker.tick(config, sweep_of('10.11.0.21', '10.11.0.222', now=later),
                            client=forge_client(quiet), now=later)
        self.assertEqual(second['proposals'], first['proposals'], 'a re-tick must not open a second review')
        self.assertEqual(quiet.calls, [], 'the stored receipt is the answer, not a second pull request')

    def test_the_forge_receipt_shares_the_proposals_directory_so_a_glob_is_not_a_read(self):
        """Guard for the 2026-09-08 CI flake: two `*.json` documents live there, and they disagree.

        `worker.tick` writes the proposal as `<key>.json` and, once a review pull request opens, the
        receipt as `<key>.result.json`: one directory, one `*.json` pattern, two different `status`
        values. Nothing else differed between the two CI runs - same tree, same fixtures, same
        fresh temporary directories - so the assertion that passed in the first run and failed in
        the second was reading whichever file `readdir` happened to name first. NTFS lists in name
        order, which is why this host cannot show that failure naturally; both listings are
        asserted below instead of only the one this machine gives.
        """
        config = {**base_config(self.root, self.index_path),
                  'proposal_allowlist': [digest(['network-sweep', '10.11.0.222'])],
                  'forge': {'repository': 'owner/inventory', 'branch': 'main', 'path': 'inventory/declared.yaml'}}
        worker.tick(config, sweep_of('10.11.0.21', '10.11.0.222'), client=forge_client(FakeForge()), now=NOW)
        listing = list((self.root/'state'/'proposals').glob('*.json'))
        self.assertEqual(len(listing), 2, 'the proposal and its receipt match one glob')
        self.assertEqual(sorted(json.loads(path.read_text())['status'] for path in listing),
                         ['created', 'needs_review'], 'so the two documents differ, and the read must choose')
        for order in (listing, list(reversed(listing))):
            selected = proposal_documents(order)
            self.assertEqual(len(selected), 1, 'exactly one proposal; a receipt never answers as one')
            self.assertFalse(selected[0].name.endswith(RECEIPT_SUFFIX),
                             'the document this test reads must be the proposal, not the review receipt')
            self.assertEqual(json.loads(selected[0].read_text())['status'], 'needs_review')
        self.assertEqual(proposal_documents(listing), proposal_documents(list(reversed(listing))),
                         'the pick depends on the two file names, never on the order readdir returned them')

    def test_a_swept_host_that_matches_a_declaration_opens_nothing_at_all(self):
        # 10.11.0.21 is probe-1's declared address, so the sweep resolves rather than proposing.
        config = {**base_config(self.root, self.index_path),
                  'proposal_allowlist': [digest(['network-sweep', '10.11.0.21'])]}
        forge = FakeForge()
        state = worker.tick(config, sweep_of('10.11.0.21'), client=forge_client(forge), now=NOW)
        self.assertEqual(state['proposals'], [])
        self.assertEqual(forge.pulls, [], 'a declared host is not a discovery proposal')
        findings = json.loads((self.root/'state'/'drift.json').read_text())['findings']
        self.assertEqual({item['kind'] for item in findings}, {'changed'})
        self.assertEqual(list(findings[0]['differences']), ['name'],
                         'the swept name is the address, which differs from the declared name')
        self.assertEqual(findings[0]['resource_id'], self.declared['resources'][0]['id'])
        self.assertEqual(list((self.root/'state'/'proposals').glob('*.json')), [])


class AgeingTests(unittest.TestCase):
    """`reconcile`'s rule without its write: age with evidence, refuse when silence is not proof."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)/'observations.db'

    def observation(self, identifier, moment, *, source='sweep-demo'):
        """One host claim whose alias is derived from its id, so two ids never share an address."""
        return discovery.Observation(source=source, observed_at=moment, observation_id=identifier,
                                    aliases=({'type': 'ip', 'value': '10.11.0.' + identifier.lstrip('h')},),
                                    attributes={'discovered_by': 'network-sweep'},
                                    evidence=('sweep:10.11.0.0/24',), kind='host', name='host-' + identifier)

    def append(self, identifiers, moment, *, complete=True, source='sweep-demo'):
        document = discovery.snapshot(source, [self.observation(item, moment, source=source)
                                              for item in identifiers], now=moment, complete=complete)
        discovery.ingest(self.db, document, now=moment)
        return document

    def test_a_silence_beyond_grace_is_aged_with_evidence_and_the_row_stays(self):
        self.append(['h1', 'h2'], NOW)
        later = NOW + dt.timedelta(hours=2)
        self.append(['h1'], later)
        before = self.db.read_bytes()
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900)
        self.assertEqual(report['status'], 'evaluated')
        self.assertEqual([item['observation_id'] for item in report['aged_out']], ['h2'])
        aged = report['aged_out'][0]
        self.assertEqual(aged['last_seen_observed_at'], utc_text(NOW))
        self.assertEqual(aged['silent_seconds'], 7200)
        self.assertEqual(aged['evidence'], ['sweep:10.11.0.0/24'])
        self.assertIs(aged['removed'], False)
        self.assertEqual(aged['evidence'], list(self.observation('h2', NOW).evidence))
        self.assertEqual(report['observed_at'], utc_text(later))
        self.assertFalse(report['history_truncated'])
        self.assertEqual(self.db.read_bytes(), before, 'aging must not rewrite the observed plane')
        self.assertEqual(len(discovery.history(self.db, 'sweep-demo')), 2)

    def test_an_aging_report_is_reproducible_for_the_same_instant(self):
        self.append(['h1', 'h2'], NOW)
        self.append(['h1'], NOW + dt.timedelta(hours=2))
        moment = NOW + dt.timedelta(hours=3)
        self.assertEqual(discovery.ageing(self.db, 'sweep-demo', now=moment, grace_seconds=900),
                         discovery.ageing(self.db, 'sweep-demo', now=moment, grace_seconds=900))

    def test_a_round_that_would_age_more_than_the_cap_refuses_with_counts_and_no_names(self):
        """A prober that died and an empty network seal the same snapshot, so neither may conclude."""
        self.append(['h1', 'h2', 'h3', 'h4'], NOW)
        later = NOW + dt.timedelta(hours=2)
        self.append([], later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('ageing_capped', 'mass_silence_above_cap', []))
        self.assertEqual((report['known_observations'], report['aged_candidates'], report['allowed_aged']),
                         (4, 4, 2))
        self.assertEqual(report['max_aged_percent'], 50)
        text = json.dumps(report)
        for identifier in ('h1', 'h2', 'h3', 'h4', 'observation_id'):
            self.assertNotIn(identifier, text, f'the refusal names {identifier}: counts only')
        self.assertEqual(len(discovery.history(self.db, 'sweep-demo')), 2,
                         'the refused round wrote nothing to the append-only plane')

    def test_the_cap_asked_away_explicitly_ages_the_whole_silent_plan(self):
        """`max_aged_percent=100` is the old behaviour, available to an operator who wants it."""
        self.append(['h1', 'h2', 'h3', 'h4'], NOW)
        later = NOW + dt.timedelta(hours=2)
        self.append([], later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900, max_aged_percent=100)
        self.assertEqual(report['status'], 'evaluated')
        self.assertEqual([item['observation_id'] for item in report['aged_out']], ['h1', 'h2', 'h3', 'h4'])
        self.assertEqual((report['known_observations'], report['aged_candidates'], report['allowed_aged']),
                         (4, 4, 4))

    def test_a_single_known_observation_still_ages_because_the_cap_floors_at_one(self):
        """`1 * 50 // 100` is zero: without the floor a source that ever saw one host could never age it."""
        self.append(['h1'], NOW)
        later = NOW + dt.timedelta(hours=2)
        self.append([], later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900)
        self.assertEqual(report['status'], 'evaluated')
        self.assertEqual([item['observation_id'] for item in report['aged_out']], ['h1'])
        self.assertEqual((report['known_observations'], report['allowed_aged']), (1, 1))

    def test_a_round_inside_the_cap_still_ages_with_evidence(self):
        """The cap is a fraction, not a freeze: half of four going silent is under the default."""
        self.append(['h1', 'h2', 'h3', 'h4'], NOW)
        later = NOW + dt.timedelta(hours=2)
        self.append(['h1', 'h2'], later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900)
        self.assertEqual(report['status'], 'evaluated')
        self.assertEqual([item['observation_id'] for item in report['aged_out']], ['h3', 'h4'])
        self.assertEqual((report['known_observations'], report['aged_candidates'], report['allowed_aged']),
                         (4, 2, 2))

    def _quiet_plan_tick(self, root: Path, index_path: Path, *, cap: int | None) -> tuple[dict, Path]:
        """Two ticks over one two-address plan, the second seeing nothing; return cursor state + dir.

        `cap` is the worker's optional `ageing_max_aged_percent` key: `None` leaves it out of the
        config entirely, which is how the default and an explicit ask stay distinguishable.
        """
        state = root/('ageing-default' if cap is None else f'ageing-cap-{cap}')
        config = {**base_config(root, index_path), 'ageing_grace_seconds': 900, 'state': str(state)}
        if cap is not None:
            config['ageing_max_aged_percent'] = cap
        worker.tick(config, sweep_of('10.11.0.5', '10.11.0.9'), now=NOW)
        later = NOW + dt.timedelta(hours=2)
        quiet = sweep_provider.SweepProvider(source='sweep-demo', cidrs=['10.11.0.5/32', '10.11.0.9/32'],
                                             sweep_allowlist=[Q5], prober=no_probe, now=later)
        return worker.tick(config, quiet, now=later), state

    def test_the_worker_carries_the_cap_and_logs_once_when_a_round_refuses(self):
        """A refusal that leaves no line in the log is the same silence this cap exists to break."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = build_index(root)
            with self.assertLogs('local_observe.inventory.worker', level='WARNING') as captured:
                state, refusal_dir = self._quiet_plan_tick(root, index_path, cap=None)
            self.assertEqual(state['ageing'], 'ageing_capped')
            self.assertEqual(state['aged_out'], 0, 'a refused round ages nothing')
            self.assertEqual(len(captured.output), 1, captured.output)
            record = captured.records[0]
            self.assertEqual(record.source, 'sweep-demo')
            self.assertEqual((record.known_observations, record.aged_candidates, record.allowed_aged),
                             (2, 2, 1), 'the line names the counts, not the identifiers')
            self.assertFalse(hasattr(record, 'observation_id'), 'a refusal must not log a list to act on')
            receipt = json.loads((refusal_dir/'ageing.json').read_text())
            self.assertEqual((receipt['known_observations'], receipt['aged_candidates'],
                              receipt['allowed_aged']), (2, 2, 1))
            asked, _ = self._quiet_plan_tick(root, index_path, cap=100)
            self.assertEqual([asked['ageing'], asked['aged_out']], ['evaluated', 2],
                             'the key reaches discovery.ageing when the config names it')

    def test_a_stale_source_reports_staleness_and_names_nobody_as_gone(self):
        self.append(['h1', 'h2'], NOW)
        report = discovery.ageing(self.db, 'sweep-demo', now=NOW + dt.timedelta(hours=6), grace_seconds=60)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('source_stale', 'snapshot_stale', []))

    def test_a_partial_latest_snapshot_concludes_nothing(self):
        self.append(['h1'], NOW)
        self.append([], NOW + dt.timedelta(minutes=5), complete=False)
        report = discovery.ageing(self.db, 'sweep-demo', now=NOW + dt.timedelta(minutes=5), grace_seconds=60)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('coverage_incomplete', 'newest_snapshot_partial', []))

    def test_an_error_snapshot_carries_its_own_code_and_ages_nothing(self):
        self.append(['h1'], NOW)
        moment = NOW + dt.timedelta(minutes=5)
        discovery.ingest(self.db, discovery.error_snapshot('sweep-demo', 'daemon_unreachable', now=moment),
                         now=moment)
        report = discovery.ageing(self.db, 'sweep-demo', now=moment, grace_seconds=60)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('source_unavailable', 'daemon_unreachable', []))

    def test_a_source_that_never_reported_is_unavailable_rather_than_empty(self):
        self.append(['h1'], NOW)
        report = discovery.ageing(self.db, 'other-source', now=NOW)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('source_unavailable', 'no_snapshot', []))

    def test_nothing_is_aged_while_the_silence_is_shorter_than_grace(self):
        self.append(['h1'], NOW)
        self.append([], NOW + dt.timedelta(minutes=10))
        report = discovery.ageing(self.db, 'sweep-demo', now=NOW + dt.timedelta(minutes=10), grace_seconds=3600)
        self.assertEqual((report['status'], report['aged_out']), ('evaluated', []))

    def test_bounds_are_refused_rather_than_interpreted(self):
        for kwargs in ({'grace_seconds': 0}, {'grace_seconds': 604801}, {'max_age_seconds': 0},
                       {'history_limit': 1}, {'history_limit': 1001}, {'max_aged_percent': 0},
                       {'max_aged_percent': 101}):
            with self.subTest(**kwargs):
                with self.assertRaises(InvalidInventory):
                    discovery.ageing(self.db, 'sweep-demo', now=NOW, **kwargs)

    def test_a_short_history_says_it_was_short_rather_than_naming_the_unseen_as_gone(self):
        """h2 disappears beyond the bound: the report must admit it did not read that far back."""
        self.append(['h1', 'h2'], NOW)
        self.append(['h1'], NOW + dt.timedelta(minutes=10))
        for offset in range(3):
            self.append(['h1'], NOW + dt.timedelta(minutes=20 + offset))
        moment = NOW + dt.timedelta(minutes=22)
        report = discovery.ageing(self.db, 'sweep-demo', now=moment, grace_seconds=600, history_limit=3)
        self.assertEqual(report['status'], 'evaluated')
        self.assertTrue(report['history_truncated'])
        self.assertEqual(report['aged_out'], [], 'an unread page is not evidence')

    def test_history_reads_newest_first_and_stops_at_its_bound(self):
        for offset in range(5):
            self.append(['h1'], NOW + dt.timedelta(minutes=offset))
        rows = discovery.history(self.db, 'sweep-demo', limit=3)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row['observed_at'] for row in rows],
                         sorted([row['observed_at'] for row in rows], reverse=True))
        self.assertEqual(discovery.latest(self.db, 'sweep-demo')['observed_at'], rows[0]['observed_at'])

    def test_history_refuses_a_database_that_is_not_the_observed_plane(self):
        with tempfile.TemporaryDirectory() as directory:
            other = build_index(Path(directory))
            with self.assertRaises(InvalidInventory):
                discovery.history(other, 'sweep-demo')

    def test_ageing_a_source_with_a_partial_history_still_needs_a_complete_edge(self):
        """An older complete snapshot does not license aging against a newer partial read."""
        self.append(['h1'], NOW, complete=True)
        later = NOW + dt.timedelta(hours=2)
        self.append(['h2'], later, complete=False)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=60)
        self.assertEqual((report['status'], report['aged_out']), ('coverage_incomplete', []))


class SealOfTheSnapshotTests(unittest.TestCase):
    """The envelope is built, not guessed: every provider path runs through discovery.snapshot()."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)/'observations.db'

    def observation(self, identifier='one', *, source='sweep-demo', moment=NOW):
        return discovery.Observation(source=source, observed_at=moment, observation_id=identifier,
                                    aliases=({'type': 'ip', 'value': '10.11.0.30'},),
                                    attributes={'discovered_by': 'network-sweep'},
                                    evidence=('sweep:10.11.0.0/24',), kind='host', name='host-a')

    def test_an_evidence_free_observation_is_refused_at_the_seal(self):
        bare = discovery.Observation(source='sweep-demo', observed_at=NOW, observation_id='one',
                                    aliases=({'type': 'ip', 'value': '10.11.0.30'},), attributes={},
                                    kind='host', name='host-a')
        with self.assertRaises(InvalidInventory):
            discovery.snapshot('sweep-demo', [bare], now=NOW)

    def test_a_mixed_source_snapshot_is_refused_because_a_source_is_one_scoped_read(self):
        with self.assertRaises(InvalidInventory):
            discovery.snapshot('sweep-demo', [self.observation(), self.observation('two', source='other')],
                              now=NOW)

    def test_a_naive_observation_time_is_refused(self):
        naive = self.observation()
        object.__setattr__(naive, 'observed_at', dt.datetime(2026, 9, 6, 12, 1))
        with self.assertRaises(InvalidInventory):
            discovery.snapshot('sweep-demo', [naive], now=NOW)

    def test_a_credential_shaped_attribute_never_becomes_a_snapshot(self):
        # The screen is validation.is_secret_key: the flattened name or its last word must be a
        # marker, which is what now refuses api_token (the gap the flattened-name rule left open).
        for key in ('client_secret', 'password', 'token', 'api_key', 'api_token', 'apiToken',
                    'API_TOKEN', 'db_password', 'bearer_token', 'claim_token'):
            with self.subTest(key=key):
                secret = self.observation()
                secret.attributes[key] = 'a-value-that-must-not-travel'
                with self.assertRaises(InvalidInventory):
                    discovery.snapshot('sweep-demo', [secret], now=NOW)

    def test_a_name_naming_a_pointer_to_a_credential_still_seals(self):
        """The positive control: a screen that refuses every name holding a marker is not a screen.

        `token_file`/`token_id`/`secret_ref` point at a credential (the declared schema carries
        `credential_refs` for exactly that) and `prompt_tokens`/`max_tokens`/`token_hash` are
        telemetry this product exists to carry, so all six must survive the screen.
        """
        for key in ('token_file', 'token_id', 'secret_ref', 'prompt_tokens', 'max_tokens', 'token_hash'):
            with self.subTest(key=key):
                item = self.observation()
                item.attributes[key] = 'a-value-that-may-travel'
                document = discovery.snapshot('sweep-demo', [item], now=NOW)
                self.assertEqual(sorted(document['observations'][0]['attributes']),
                                 sorted(['discovered_by', key]))

    def test_an_unbounded_source_name_is_refused(self):
        for bad in ('Sweep Demo', '10.11.0.0', ''):
            with self.subTest(source=bad):
                with self.assertRaises(InvalidInventory):
                    discovery.snapshot(bad, [], now=NOW)

    def test_the_envelope_adopts_the_observation_time_not_the_caller_clock(self):
        earlier = NOW - dt.timedelta(seconds=30)
        document = discovery.snapshot('sweep-demo', [self.observation(moment=earlier)], now=NOW)
        self.assertEqual(document['observed_at'], utc_text(earlier))
        self.assertEqual(document['scope'], [])
        self.assertEqual(document['status'], 'ok')
        discovery.ingest(self.db, document, now=NOW)
        self.assertEqual(discovery.latest(self.db, 'sweep-demo')['snapshot_id'], document['snapshot_id'])

    def test_complete_is_an_explicit_claim_and_never_a_default(self):
        """Absence can only be evidenced by a read that said it was whole, so the flag must be typed."""
        self.assertFalse(discovery.snapshot('sweep-demo', [self.observation()], now=NOW)['complete'])
        self.assertTrue(discovery.snapshot('sweep-demo', [self.observation()], now=NOW,
                                          complete=True)['complete'])

    def test_an_error_snapshot_may_not_name_itself_arbitrarily(self):
        with self.assertRaises(InvalidInventory):
            discovery.error_snapshot('sweep-demo', 'BAD CODE')
        with self.assertRaises(InvalidInventory):
            discovery.error_snapshot('sweep demo', 'unavailable')


class CollisionTests(unittest.TestCase):
    """An ambiguous identity is surfaced with evidence, and it cannot become a declaration."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = build_index(self.root)
        self.db = self.root/'observations.db'
        self.document = read_document(ROOT/'examples/inventory/declared.yaml')
        self.host = self.document['resources'][0]['id']
        self.service = self.document['resources'][1]['id']

    def test_a_provider_observation_matching_two_declarations_is_unresolved_not_merged(self):
        provider = kube_of([colliding_pod()])
        discovery.ingest(self.db, provider.snapshot(), now=NOW)
        findings = discovery.drift(self.index_path, self.db, ['kube-demo'], now=NOW)['findings']
        self.assertEqual({item['kind'] for item in findings}, {'identity_unresolved', 'coverage_incomplete'})
        conflict = next(item for item in findings if item['kind'] == 'identity_unresolved')
        self.assertEqual(conflict['resolution']['status'], 'conflict')
        self.assertEqual(conflict['resolution']['candidates'], sorted([self.host, self.service]))
        self.assertIsNone(conflict['resolution']['resource_id'], 'no candidate is picked for the operator')
        self.assertEqual(conflict['evidence'], ['kube:demo/demo-api',
                                               'kube-uid:bbbbbbbb-1111-4111-8111-111111111111'])
        self.assertEqual(conflict['observed_at'], utc_text(NOW))
        self.assertFalse(any(item['kind'] in ('missing', 'changed', 'undeclared') for item in findings),
                         'an unresolved identity must not be allowed to imply anything else')

    def test_a_colliding_observation_cannot_be_proposed(self):
        provider = kube_of([colliding_pod()])
        observation = provider.observe()[0]
        discovery.ingest(self.db, provider.snapshot(), now=NOW)
        before = self.index_path.read_bytes()
        with self.assertRaises(InvalidInventory):
            discovery.propose(self.index_path, self.db, 'kube-demo', observation.observation_id,
                             self.root/'proposal.json', now=NOW)
        self.assertEqual(self.index_path.read_bytes(), before)
        self.assertFalse((self.root/'proposal.json').exists(), 'no proposal may be written for a conflict')

    def test_a_colliding_observation_never_reaches_the_forge_through_the_worker(self):
        provider = kube_of([colliding_pod()])
        config = {**base_config(self.root, self.index_path),
                  'proposal_allowlist': [provider.observe()[0].observation_id]}
        forge = FakeForge()
        state = worker.tick(config, provider, client=forge_client(forge), now=NOW)
        self.assertEqual(state['proposals'], [])
        self.assertEqual(forge.pulls, [], 'a collision opens no pull request')

    def test_two_declarations_sharing_an_alias_are_refused_before_the_index_exists(self):
        widened = copy.deepcopy(self.document)
        widened['resources'][1]['aliases'].append({'type': 'ip', 'value': '10.11.0.21'})
        with self.assertRaises(InvalidInventory):
            index.build(widened, self.root/'second.db', 'collision', now=NOW)


class WorkerSourceSelectionTests(unittest.TestCase):
    """Which source a config may name, and the one it may never name."""

    def test_a_sweep_cannot_be_named_by_a_config_file(self):
        with self.assertRaises(InvalidInventory) as caught:
            worker.provider_from_config({'sweep': {'source': 'sweep-demo', 'cidrs': ['10.11.0.0/24']}})
        self.assertIn('prober', str(caught.exception))

    def test_a_config_naming_no_source_or_two_sources_is_refused(self):
        for config in ({}, {'docker': {}, 'kube': {}}, {'docker': {}, 'sweep': {}}):
            with self.subTest(keys=sorted(config)):
                with self.assertRaises(InvalidInventory):
                    worker.provider_from_config(config)

    def test_a_kube_config_reads_the_listing_file_it_names(self):
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory)/'pods.json'
            listing.write_text(json.dumps({'items': [{'metadata': {'name': 'solo-1', 'namespace': 'demo'},
                                                     'spec': {'containers': [{'image': 'i:1'}]},
                                                     'status': {'phase': 'Running'}}]}), encoding='utf-8')
            produce = worker.provider_from_config({'kube': {'source': 'kube-demo',
                                                           'listing_file': str(listing)}})
            result = produce()
            self.assertEqual([item['name'] for item in result['observations']], ['demo/solo-1'])
            with self.assertRaises(InvalidInventory):
                worker.provider_from_config({'kube': {'source': 'kube-demo'}})

    def test_a_docker_config_still_builds_the_shipped_source(self):
        produce = worker.provider_from_config({'docker': {'projects': ['demo'], 'source': 'demo-docker',
                                                          'socket': '/run/user/1001/docker.sock',
                                                          'expected_root': '/stage/docker'}})
        with patch('local_observe.inventory.docker_provider.subprocess.run',
                   side_effect=docker_cli([{'id': 'a' * 64, 'service': 'api'}])):
            result = produce()
        self.assertEqual(result['source'], 'demo-docker')
        self.assertEqual(result['observations'][0]['attributes']['replicas'], 1)

    def test_tick_accepts_a_provider_object_and_a_bare_callable_alike(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index_path = build_index(root)
            provider = sweep_of('10.11.0.5', '10.11.0.9')
            config = {**base_config(root, index_path), 'ageing_grace_seconds': 900}
            as_object = worker.tick(config, provider, now=NOW)
            as_callable = worker.tick({**config, 'state': str(root/'state-b')},
                                     lambda: provider.snapshot(), now=NOW)
            self.assertEqual(as_object['observations'], as_callable['observations'])
            self.assertEqual(as_object['findings'], as_callable['findings'])
            self.assertEqual([as_object['ageing'], as_callable['ageing']], ['evaluated', 'evaluated'])
            self.assertEqual([as_object['aged_out'], as_callable['aged_out']], [0, 0])
            self.assertEqual(as_object['proposals'], [])


if __name__ == '__main__':
    unittest.main()
