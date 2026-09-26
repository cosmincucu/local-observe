"""The job-observe component: its documents, its manifest shape, and the inertness of the opt-ins.

job observe standard adds a component the gate has never seen (`components/control/job-observe/`) and a collector
receiver that must not collect until an operator says so. Everything here is static: the loader
`scripts/check_foundation.py` uses, and the same model rules it enforces. No container is involved --
this repository has no Docker in the test path and no claim to make about one. The runtime proof
lives in the component's own `conformance.md`, which is honest about not having been run.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks

COMPONENT = ROOT / 'components' / 'control' / 'job-observe'
REQUIRED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):\?")
DEFAULTED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]*)\}")


def template_values(example):
    return dict(re.findall(r"(?m)^([A-Z0-9_]+)=(.*)$",
                           (example.parent / ".env.example").read_text(encoding="utf-8")))


class ComponentDocumentsTests(unittest.TestCase):
    def test_the_four_lifecycle_documents_and_the_pin_exist(self):
        """A shipped component owes the same set every other component carries, not a shorter one."""
        for name in ('compose.yaml', 'versions.json', 'CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md'):
            with self.subTest(document=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_contract_cites_the_version_and_the_source_of_every_claim(self):
        """No guessing: an upstream claim names a file at a tag, and anything unproven says UNVERIFIED."""
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        self.assertIn('v4.4', contract)
        self.assertIn('v0.7.0', contract)
        self.assertIn('BSD-3-Clause', contract)
        self.assertIn('Apache-2.0', contract)
        self.assertIn('UNVERIFIED', contract)
        self.assertIn('github.com/healthchecks/healthchecks', contract)   # upstream docs are linked
        self.assertIn('availability', contract)                           # the event-kind answer is in it
        for metric in ('hc_check_up', 'hc_check_grace', 'systemd_unit_state'):
            with self.subTest(metric=metric):
                self.assertIn(metric, contract)

    def test_the_pin_file_states_that_nothing_has_been_run(self):
        import json
        pins = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.assertEqual(pins['status'], 'selected')
        self.assertIsNone(pins['verified_on'])
        self.assertRegex(pins['healthchecks']['image_digest_amd64'], r'^sha256:[a-f0-9]{64}$')
        self.assertRegex(pins['systemd_exporter']['image_digest_amd64'], r'^sha256:[a-f0-9]{64}$')


class ManifestShapeTests(unittest.TestCase):
    def setUp(self):
        self.model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.service = self.model['services']['healthchecks']

    def test_the_manifest_passes_the_model_rules_it_ships_under(self):
        self.assertEqual(checks.check_model(self.model, COMPONENT), [])
        self.assertEqual(checks.check_credential_files(self.model), [])

    def test_the_image_is_a_required_variable_and_the_port_is_loopback(self):
        self.assertTrue(checks.IMAGE_VARIABLE.fullmatch(self.service['image']))
        self.assertTrue(self.service['ports'][0].startswith('127.0.0.1:'))
        self.assertEqual(self.service['platform'], 'linux/amd64')
        self.assertEqual(self.service['pull_policy'], 'always')

    def test_the_only_secret_value_is_the_path_of_a_mounted_file(self):
        """secret files: the environment names a path; the value arrives from under /run/secrets/."""
        environment = checks.compose_environment(self.service)
        self.assertEqual(environment['SECRET_KEY_FILE'], '/run/secrets/healthchecks-secret')
        self.assertNotIn('SECRET_KEY', environment)                       # upstream prefers *_FILE
        self.assertEqual(checks.declared_secret_names(self.service), ['healthchecks-secret'])
        self.assertIn('healthchecks-secret', self.model['secrets'])
        host_file = self.model['secrets']['healthchecks-secret']['file']
        self.assertRegex(host_file, r'^\$\{LO_HEALTHCHECKS_SECRET_FILE:\?.+\}$')

    def test_the_state_lives_on_a_project_scoped_volume_and_the_logs_are_bounded(self):
        self.assertIn('healthchecks-data:/data', [str(v) for v in self.service['volumes']])
        self.assertEqual(self.model['volumes'], {'healthchecks-data': None})
        self.assertEqual(self.service['logging']['driver'], 'json-file')
        self.assertIn('max-size', self.service['logging']['options'])

    def test_a_healthcheck_probes_the_database_backed_status_route(self):
        """'healthy' here must mean the app answers AND the SQLite file is readable."""
        healthcheck = self.service['healthcheck']
        self.assertEqual(healthcheck['test'][0], 'CMD')
        self.assertIn('fetchstatus.py', ' '.join(healthcheck['test']))
        for key in ('interval', 'timeout', 'retries', 'start_period'):
            self.assertIn(key, healthcheck)

    def test_no_compose_manifest_in_this_project_runs_systemd_exporter(self):
        """It is a per-host agent; making it a service here would mean mounting a control socket.

        Checked on the models, not the prose: this component's own comments name the exporter, which
        is exactly the documentation job observation asked for. What must not exist is a service or an image
        variable for it anywhere under components/.
        """
        for path in ROOT.joinpath('components').rglob('compose.yaml'):
            model = checks.read_yaml(path)
            with self.subTest(manifest=path.relative_to(ROOT).as_posix()):
                self.assertEqual([name for name in model.get('services', {}) if 'systemd' in name.lower()], [])
                self.assertFalse([variable for variable in
                                  (set(self._variables(path)) | set(model.get('secrets') or {}))
                                  if 'SYSTEMD' in variable.upper()])

    @staticmethod
    def _variables(path):
        return re.findall(r'\$\{([A-Z0-9_]+)', path.read_text(encoding='utf-8'))

    def test_the_agent_contract_documents_the_exporter_it_replaces(self):
        """job observation's per-host half is documentation until an operator enables it; the doc must be complete."""
        contract = (ROOT / 'components' / 'data' / 'agent-linux' / 'CONTRACT.md').read_text(encoding='utf-8')
        for claim in ('systemd_exporter', 'systemd_unit_state', 'systemd_timer_last_trigger_seconds',
                      'job observation', '9558', 'UNVERIFIED'):
            with self.subTest(claim=claim):
                self.assertIn(claim, contract)


class ExampleWiringTests(unittest.TestCase):
    def test_the_full_example_includes_the_component(self):
        services, errors = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        self.assertEqual(errors, [])
        self.assertIn('healthchecks', services)

    def test_the_template_carries_every_variable_the_manifest_reads(self):
        example = ROOT / 'examples/full/compose.yaml'
        body = (COMPONENT / 'compose.yaml').read_text(encoding='utf-8')
        required = {match.group(1) for match in REQUIRED_VARIABLE.finditer(body)}
        defaulted = {match.group(1) for match in DEFAULTED_VARIABLE.finditer(body)}
        keys = set(template_values(example))
        self.assertIn('LO_HEALTHCHECKS_IMAGE', required)
        self.assertEqual(sorted(required - keys), [], 'required variable with no template line')
        self.assertTrue(defaulted & keys, 'the port/site defaults are not recorded in the template')

    def test_the_published_port_is_renderable_from_the_template(self):
        example = ROOT / 'examples/full/compose.yaml'
        values = template_values(example)
        port = self.service_port(values)
        self.assertTrue(port.startswith('127.0.0.1:'), port)
        self.assertNotEqual(port.split(':')[1], '', 'published port renders empty from the template')
        host_ports = [p.split(':')[1] for p in self.all_example_ports(values)]
        self.assertEqual(len(host_ports), len(set(host_ports)), 'two services publish one host port')

    def service_port(self, values):
        return self._render(checks.read_yaml(COMPONENT / 'compose.yaml')['services']['healthchecks']['ports'][0],
                            values)

    def all_example_ports(self, values):
        services, _ = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        return [self._render(port, values) for service in services.values() for port in service.get('ports', [])]

    @staticmethod
    def _render(value, values):
        value = REQUIRED_VARIABLE.sub(lambda match: values.get(match.group(1), ''), value)
        return DEFAULTED_VARIABLE.sub(lambda match: values.get(match.group(1)) or match.group(2), value)


class AgentOptInTests(unittest.TestCase):
    """The per-host half must ship inert: an unrequested scrape is a cardinality decision nobody made."""

    def setUp(self):
        self.collector = checks.read_yaml(ROOT / 'components' / 'data' / 'agent-linux' / 'collector.yaml')

    def test_the_collector_config_is_still_consistent(self):
        self.assertEqual(checks.check_collector(self.collector, 'agent-linux'), [])

    def test_the_scrape_receiver_exists_but_names_no_pipeline(self):
        self.assertIn('prometheus/job-observe', self.collector['receivers'])
        referenced = {component for pipeline in self.collector['service']['pipelines'].values()
                      for kind, parts in pipeline.items() if kind == 'receivers' for component in parts}
        self.assertNotIn('prometheus/job-observe', referenced)
        self.assertEqual(self.collector['service']['pipelines']['metrics']['receivers'], ['hostmetrics'])

    def test_every_environment_variable_the_collector_reads_is_one_the_agent_manifest_exports(self):
        """A ${env:…} the agent's compose file never exports stops the agent booting on every host.

        agent-linux/compose.yaml is outside job observe standard's file list, so the opt-in scrape block could not add
        a variable even if a variable were the right shape for it: this asserts the new receiver is
        self-contained (a literal target an operator edits) and that the file exports nothing new.
        """
        collector = (ROOT / 'components' / 'data' / 'agent-linux' / 'collector.yaml').read_text(encoding='utf-8')
        wanted = set(re.findall(r'\$\{env:([A-Z0-9_]+)\}', collector))
        manifest = checks.read_yaml(ROOT / 'components' / 'data' / 'agent-linux' / 'compose.yaml')
        exported = set()
        for service in manifest['services'].values():
            exported |= set(checks.compose_environment(service))
        self.assertEqual(sorted(wanted - exported), [], 'the collector reads a variable nothing exports')
        self.assertIn('9558', collector)                                  # the exporter's documented port
        self.assertIn('host-gateway-unset.example', collector)            # unreachable until edited, by design


if __name__ == '__main__':
    unittest.main()
