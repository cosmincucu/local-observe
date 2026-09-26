"""Structural tests for the `anomaly` component: the manifest, its gate coverage, and its healthcheck.

Since anomaly deployment support  `examples/full/compose.yaml` includes
`components/control/anomaly/compose.yaml`, so `check_example` — and therefore `python -B
scripts/check_foundation.py` — does reach it through the shipped composition. What this file adds over
that is the direct read: it runs the gate's own functions over the manifest alone, so a model failure
names this component instead of an example, and it drives `check_example` with a synthetic top-level
model so the four-lifecycle-document rule fires for real on this directory and not on the example's.
(The `ai` component, which still ships in no example, was the original reason for the shape.)

Offline and structural by design: no Docker, no network, no container. The one thing that *is* executed
is the healthcheck's own code, read out of the YAML and run in a subprocess against a temporary file —
because "the producer's healthcheck turns unhealthy when it stops ticking" is the ledger's acceptance
clause and the only form of it available without a daemon (anomaly component decision D2).
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

from local_observe.platform import anomaly, anomaly_cursor

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks

COMPONENT = ROOT / 'components' / 'control' / 'anomaly'
SERVICE = 'anomaly'
LIFECYCLE_DOCUMENTS = ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md')


def service_environment() -> dict[str, str]:
    """The shipped manifest's service environment, in Compose's mapping form."""
    model = checks.read_yaml(COMPONENT / 'compose.yaml')
    return checks.compose_environment(model['services'][SERVICE])


def healthcheck_code() -> str:
    """The `python -c` source the manifest's healthcheck runs — read from the file, never copied here."""
    test = checks.read_yaml(COMPONENT / 'compose.yaml')['services'][SERVICE]['healthcheck']['test']
    assert test[:3] == ['CMD', 'python', '-c'], f'unexpected healthcheck shape: {test[:3]!r}'
    return test[3]


def run_probe(code: str, cursor: Path, allowance: str | None) -> subprocess.CompletedProcess:
    """Run the manifest's probe code in a fresh interpreter against *cursor* with *allowance*."""
    environment = dict(os.environ, LO_ANOMALY_CURSOR=str(cursor))
    if allowance is not None:
        environment['LO_ANOMALY_STALE_SECONDS'] = allowance
    return subprocess.run([sys.executable, '-B', '-c', code], env=environment,
                          capture_output=True, text=True, timeout=120, cwd=str(ROOT))


class ShippedArtefactsTests(unittest.TestCase):
    def test_the_six_artefacts_are_all_present(self):
        """A component owes the four lifecycle documents, its pin file and its manifest (quality bar)."""
        for name in LIFECYCLE_DOCUMENTS + ('versions.json', 'compose.yaml'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_manifest_passes_the_model_rules_the_gate_uses(self):
        """The same rules `check_example` now applies through `examples/full`, attributed to this file."""
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertEqual(checks.check_model(model, COMPONENT), [])
        self.assertEqual(checks.check_credential_files(model), [])

    def test_the_gate_walks_it_as_a_component_through_a_synthetic_example(self):
        """The four-document rule and the merged-model rules, over the real directory.

        `include_entry` resolves `base / entry`, and an absolute entry wins, so a top-level model
        written anywhere can name this manifest by path — which walks this component on its own, with
        no dependency on whether an example still lists it (until anomaly deployment support none did: the `ai`
        precedent,
        taken one step further, because the model rules alone would pass even if the lifecycle
        documents were deleted).
        """
        with tempfile.TemporaryDirectory() as directory:
            example = Path(directory) / 'compose.yaml'
            example.write_text(yaml.safe_dump({'include': [str(COMPONENT / 'compose.yaml')]}),
                               encoding='utf-8')
            self.assertEqual(checks.check_example(ROOT, example), [])

    def test_a_root_missing_the_documents_is_refused_by_all_four_names(self):
        """The mutation proof for the test above: without it, the four-document rule could be blind.

        The same include shape, pointed at a checkout that holds only the manifest: `check_example`
        must answer with one line per missing document, which is what makes the green assertion in the
        previous test a claim about the documents rather than about the include mechanism.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'checkout'
            component = root / 'components' / 'control' / 'anomaly'
            component.mkdir(parents=True)
            shutil.copyfile(COMPONENT / 'compose.yaml', component / 'compose.yaml')
            example = root / 'compose.yaml'
            example.write_text(yaml.safe_dump({'include': [str(component / 'compose.yaml')]}),
                               encoding='utf-8')
            errors = checks.check_example(root, example)
            expected = [f'{component.name}: missing {name}' for name in LIFECYCLE_DOCUMENTS]
            self.assertEqual(sorted(errors), sorted(expected),
                             'the lifecycle-document rule is not what this test thinks it is')

    def test_versions_json_states_every_runtime_claim_as_not_run(self):
        """The honesty of `components/control/ai/versions.json`, applied to a component with no image."""
        document = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.assertEqual(document['component'], SERVICE)
        self.assertEqual(document['status'], 'experimental')
        validation = document['validation']
        self.assertEqual(validation['runtime_conformance'], 'not-run')
        self.assertIs(validation['container_started'], False)
        self.assertIs(validation['compose_config_rendered'], False)
        # Flipped by anomaly deployment support  on 2026-09-10: examples/full/compose.yaml now names the manifest.
        # The two clauses around it are unchanged and still say no — nothing has rendered it and no
        # container has started, so inclusion is a fact about this tree and not about a deployment.
        self.assertIs(validation['component_in_an_example'], True)
        self.assertIn('examples/full/compose.yaml', validation['component_in'])
        self.assertEqual(validation['backup_restore'], 'not-run')
        self.assertEqual(validation['upgrade_rehearsal'], 'not-run')
        self.assertIn('test_anomaly_component', validation['static_gate'])
        # The measured reason this component cannot be started against the pinned platform image.
        self.assertIn('rebuild_required', document['image'])
        self.assertIsNone(document['image']['rebuild_verified_on'])


class ProbeTests(unittest.TestCase):
    """The ledger's acceptance clause, in the only offline form it has (decision D2)."""

    def test_the_probe_answers_on_the_cursor_and_nothing_else(self):
        """Fresh cursor -> 0; aged past the allowance -> 1; missing -> 1. From the manifest's own code."""
        code = healthcheck_code()
        self.assertIn('LO_ANOMALY_STALE_SECONDS', code,
                      'the allowance must be the manifest knob, not a constant copied from sigma')
        self.assertIsNone(re.search(r'getmtime\(p?\w*\) < \d', code),
                          'a hard-coded allowance in the probe is sigma\'s healthcheck, not this one')
        with tempfile.TemporaryDirectory() as directory:
            cursor = Path(directory) / 'cursor.json'
            cursor.write_text('{}', encoding='utf-8')
            fresh = run_probe(code, cursor, '30')
            self.assertEqual(fresh.returncode, 0, f'{fresh.stdout}\n{fresh.stderr}')

            aged = time.time() - 30 - 60
            os.utime(cursor, (aged, aged))
            stale = run_probe(code, cursor, '30')
            self.assertEqual(stale.returncode, 1, 'an aged cursor must read as unhealthy')
            self.assertNotIn('Traceback', stale.stderr, 'exit 1 must be the verdict, not a crash')

            cursor.unlink()
            missing = run_probe(code, cursor, '30')
            self.assertEqual(missing.returncode, 1, 'a producer that never wrote must not look healthy')
            self.assertNotIn('Traceback', missing.stderr)

            # The documented fallback: unset allowance means the shipped default, not a crash.
            too_old_to_matter = time.time() - 200
            cursor.write_text('{}', encoding='utf-8')
            os.utime(cursor, (too_old_to_matter, too_old_to_matter))
            self.assertEqual(run_probe(code, cursor, None).returncode, 0,
                             'LO_ANOMALY_STALE_SECONDS unset must fall back to 1800')

    def test_the_shipped_allowance_covers_the_shipped_defaults(self):
        """D2's formula, checked: 1800 >= max(evaluation_seconds) + 2 x tick_seconds at the defaults."""
        environment = service_environment()
        default = re.fullmatch(r'\$\{LO_ANOMALY_STALE_SECONDS:-([0-9]+)\}',
                               environment['LO_ANOMALY_STALE_SECONDS'])
        self.assertIsNotNone(default, 'the allowance must ship with a numeric default')
        tick = anomaly.DEFAULT_TICK_SECONDS
        # `load_config` defaults evaluation_seconds to tick_seconds, so the shipped default window is
        # one tick; an operator who raises it past the allowance is the one false-unhealthy case
        # CONTRACT.md names, and it cannot be checked from a manifest that cannot read the config file.
        self.assertGreaterEqual(int(default.group(1)), tick + 2 * tick)


class ModuleAgreementTests(unittest.TestCase):
    def test_the_environment_names_come_from_the_modules(self):
        """What catches a rename in two modules this item may not edit.

        `anomaly.py` and `anomaly_cursor.py` implement the producer and cursor contract. If one of them renames
        `LO_ANOMALY_CURSOR`, the failure must land here, where the two
        names are visible together, and not at a container's first refused start.
        """
        environment = service_environment()
        for name in (anomaly.CONFIG_ENVIRONMENT, anomaly.SOURCE_ENVIRONMENT,
                     anomaly_cursor.CURSOR_ENVIRONMENT):
            with self.subTest(variable=name):
                self.assertIn(name, environment)

    def test_the_container_paths_are_the_paths_the_manifest_mounts(self):
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        environment = service_environment()
        self.assertEqual(environment[anomaly.CONFIG_ENVIRONMENT], '/config/anomaly.json')
        self.assertRegex(environment[anomaly.SOURCE_ENVIRONMENT],
                         r'^\$\{LO_ANOMALY_SOURCE:\?.+\}$',
                         'the producer identity must be a required runtime value: a guessed identity '
                         'folds two producers into one event stream')
        config_mounts = [item for item in model['services'][SERVICE]['volumes']
                         if ':/config/anomaly.json' in str(item)]
        self.assertEqual(len(config_mounts), 1)
        self.assertTrue(str(config_mounts[0]).endswith(':ro'),
                        'a writable config mount breaks the gate rule it exists to keep')

    def test_the_producer_token_secret_is_this_component_s_own_host_file(self):
        """The manifest's secret sources, pinned: one credential row authenticates one identity.

        anomaly component mounted `${LO_PRODUCER_TOKEN_FILE}` — the host file the Sigma runner presents — as this
        service's `anomaly-producer-token`, while `LO_ANOMALY_SOURCE` names a different producer.
        One row of the platform's credentials file carries one `identity` and
        `local_observe/platform/state.py` refuses an event whose `source` is not that identity, so the
        shared file shipped a container that judged and was refused at intake forever . The pin is on the manifest's
        `secrets:` source, not the container-side name:
        `credentials.read_credential('LO_PRODUCER_TOKEN')` is what `anomaly.py` reads, and that module
        belongs to another agent, so the host side is the half this component owns.
        """
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        sources = {name: str((entry or {}).get('file')) for name, entry in model['secrets'].items()}
        self.assertRegex(sources['anomaly-producer-token'],
                         r'^\$\{LO_ANOMALY_PRODUCER_TOKEN_FILE:\?.+\}$',
                         'the anomaly producer must read a credential file of its own')
        self.assertNotIn('${LO_PRODUCER_TOKEN_FILE', ' '.join(sources.values()),
                         "mounting the Sigma runner's token under a second identity is the dedicated anomaly credential")
        self.assertEqual('/run/secrets/anomaly-producer-token',
                         service_environment()['LO_PRODUCER_TOKEN_FILE'],
                         'the container path is what read_credential resolves; it does not move')
        # The query credential stays deliberately shared: one store, one read-only user, one file.
        self.assertRegex(sources['anomaly-clickhouse-password'],
                         r'^\$\{LO_CLICKHOUSE_PASSWORD_FILE:\?.+\}$')

    def test_anomaly_is_not_a_host_published_service_and_declares_no_port(self):
        """A producer with two outbound connections serves nothing; the gate list must not grow."""
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertNotIn('ports', model['services'][SERVICE])
        self.assertNotIn(SERVICE, checks.HOST_PUBLISHED_SERVICES)


class CursorStateTests(unittest.TestCase):
    def test_the_cursor_lives_on_a_declared_named_volume_and_the_contract_keeps_the_mode_rule(self):
        """D3 cannot be silently dropped: the volume, the path and the `0700` sentence are all pinned.

        A fresh named volume at a path the image does not carry arrives `root:root` mode `0755`, and
        `private_parent` refuses exactly that, so a manifest that keeps the volume but loses the
        preparation section ships a service that cannot start. The string check is crude on purpose:
        the refusal text is the operator's only instruction about the mode.
        """
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertEqual(service_environment()[anomaly_cursor.CURSOR_ENVIRONMENT],
                         '/state/cursor.json')
        self.assertIn('anomaly-state', model.get('volumes') or {},
                      'the cursor needs a writable volume; no bind can be one and stay gateable')
        self.assertIn('anomaly-state:/state', model['services'][SERVICE]['volumes'])
        self.assertIn('must be mode 0700', (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
