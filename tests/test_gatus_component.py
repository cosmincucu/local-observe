"""The `synthetics` component: its documents, its manifest, its pin, and the shape of its Gatus config.

synthetics component turned a staging wiring into a component directory, which means everything a component owes can
now be checked statically — and everything it must NOT contain can be refused statically too. Nothing
here starts a container: the loader and the model rules are the ones
`scripts/check_foundation.py` enforces on every shipped example, and the rest are the promises that
only this component makes (a `security:` block that exists and carries no real credential, an endpoint
key that agrees with the URL the adapter is configured to call, a digest that names a release rather
than a channel, and one mirror value that must not drift from its authority).

The runtime half of the story is `components/control/synthetics/conformance.md`, and that file reports
almost every row `not-run`. This one proves nothing about a running engine.
"""
import base64
import binascii
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks

COMPONENT = ROOT / 'components' / 'control' / 'synthetics'
PINNED_RELEASE = 'v5.36.0'
SUPERSEDED = 'sha256:52bf60b1e1c431a6d6ab0342c27d92898b51192c117dece05f5751681fa27d63'
AMD64_DIGEST = 'sha256:8df964117ac6a78749ec8cd00039a499268156b874c3a110dc58de7e312c1ab5'
REQUIRED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):\?")
DEFAULTED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]*)\}")


def template_values(example):
    """The example's own `.env.example` as a mapping, for rendering `${VAR:?}`/`${VAR:-x}` lines."""
    return dict(re.findall(r"(?m)^([A-Z0-9_]+)=(.*)$", (example.parent / '.env.example').read_text(encoding='utf-8')))


def derived_key(group: str, name: str) -> str:
    """Gatus's endpoint key, as a Python mirror of upstream's rule.

    `config/key/key.go` at v5.36.0: `sanitize(group) + "_" + sanitize(name)`, where `sanitize`
    lowercases and maps `/ _ . , space # + &` to `-`. This is a re-implementation on purpose: the
    point is to refuse a shipped config whose key would not match the URL its own adapter is
    configured to call, and the only way to test that is to derive it independently of both files.
    """

    def sanitize(value: str) -> str:
        value = value.strip().lower()
        for character in '/_. ,#&+':
            value = value.replace(character, '-')
        return value
    return f"{sanitize(group)}_{sanitize(name)}"


class ComponentDocumentsTests(unittest.TestCase):
    def test_the_component_ships_the_five_artefacts_and_the_four_lifecycle_documents(self):
        for name in ('compose.yaml', 'versions.json', 'config.yaml', 'CONTRACT.md', 'backup.md',
                     'upgrade.md', 'conformance.md'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_contract_cites_upstream_and_marks_what_was_never_sent(self):
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        for claim in (PINNED_RELEASE, 'api/api.go', 'security/config.go', 'security/basic.go',
                      'config/key/key.go', 'os.ExpandEnv', 'UNVERIFIED', 'gatus for synthetics', 'outside-in probes', 'overlay compatibility',
                      'path monitoring', 'synthetic assertions', 'FROM scratch'):
            with self.subTest(claim=claim):
                self.assertIn(claim, contract)
        self.assertIn('Basic', contract)
        # The decision that the surviving bespoke layer is not here must be stated, not implied.
        self.assertIn('netpath', contract)

    def test_the_conformance_record_reports_one_of_the_three_words_for_every_row(self):
        body = (COMPONENT / 'conformance.md').read_text(encoding='utf-8')
        rows = [line for line in body.splitlines() if re.match(r'\|\s*\d+\s*\|', line)]
        self.assertGreaterEqual(len(rows), 12, 'the results table is the record; a short one is a claim')
        for row in rows:
            with self.subTest(row=row[:60]):
                self.assertTrue(re.search(r'\*\*(pass|fail|not-run)\*\*', row),
                                'every check reports pass, fail or not-run (docs/CONTRACTS.md §6)')
        self.assertIn('not-run', body)
        for scenario in ('Failure to recovery', 'absent-engine', 'coverage'):
            with self.subTest(scenario=scenario):
                self.assertIn(scenario, body)

    def test_backup_names_the_two_units_and_the_duplicate_policy(self):
        body = (COMPONENT / 'backup.md').read_text(encoding='utf-8')
        for unit in ('gatus-data', 'cursor.json', 'detector-data'):
            with self.subTest(unit=unit):
                self.assertIn(unit, body)
        # docs/CONTRACTS.md §7 requires the replay/duplicate policy next to the cursor.
        for promise in ('UNIQUE(source, source_event_id)', 'source_event_id', 'idempotent'):
            with self.subTest(promise=promise):
                self.assertIn(promise, body)

    def test_upgrade_answers_the_in_flight_window_question(self):
        body = (COMPONENT / 'upgrade.md').read_text(encoding='utf-8')
        for case in ('In-flight windows', 'pending', 'coverage', 'Downgrade', 'watermark'):
            with self.subTest(case=case):
                self.assertIn(case, body)
        self.assertIn('No Gatus version upgrade has been', body,
                      'the admission that nothing has been rehearsed travels with the recipe')


class PinTests(unittest.TestCase):
    def setUp(self):
        self.pins = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))

    def test_the_pin_names_a_release_tag_and_a_digest_resolved_by_self_hash(self):
        self.assertEqual(PINNED_RELEASE, self.pins['release']['tag'])
        self.assertEqual(AMD64_DIGEST, self.pins['digests']['value_used_by_LO_GATUS_IMAGE'])
        self.assertEqual(f'twinproduction/gatus@{AMD64_DIGEST}', self.pins['image'],
                         'the value an operator copies into LO_GATUS_IMAGE is the one under review')
        self.assertIn('registry-1.docker.io', self.pins['digest_provenance']['registry_url'])
        self.assertEqual('2026-09-09', self.pins['digest_provenance']['read_on'])
        self.assertIn('sha256 of the manifest bytes', self.pins['digests']['verified_by'])

    def test_the_status_and_verified_on_agree_that_nothing_was_run(self):
        self.assertEqual('experimental', self.pins['status'])
        self.assertIsNone(self.pins['verified_on'])
        self.assertIn('not-run', self.pins['runtime_state'])

    def test_the_superseded_digest_is_named_with_the_reason_and_not_deleted(self):
        superseded = self.pins['superseded_digest']
        self.assertEqual(SUPERSEDED, superseded['value'])
        self.assertIn('could not be attributed to a release', superseded['why_it_was_rejected'])
        self.assertIn('components/control/platform/versions.json', superseded['where_it_lived'])
        self.assertIn('audit trail', superseded['why_it_was_rejected'] + str(superseded))

    def test_the_platform_mirror_carries_the_same_digest_and_says_who_is_authoritative(self):
        platform = json.loads((ROOT / 'components' / 'control' / 'platform' / 'versions.json')
                              .read_text(encoding='utf-8'))
        self.assertEqual(f'twinproduction/gatus@{AMD64_DIGEST}', platform['gatus_image'],
                         'the compatibility mirror must never disagree with the owning component')
        self.assertIn('MIRROR ONLY', platform['gatus_image_note'])
        self.assertEqual('components/control/synthetics/versions.json', self.pins['mirror']['authority'])
        self.assertIn('authoritative', self.pins['mirror']['authority_rule'])
        self.assertEqual('gatus_image', self.pins['mirror']['key'])
        # The catalogue names the authority; the compatibility mirror still has its equality guard.

        seed = json.loads((ROOT / 'examples' / 'catalog' / 'gatus-synthetics' / 'entry.json')
                          .read_text(encoding='utf-8'))
        self.assertEqual('components/control/synthetics/versions.json', seed['components'][0]['pin']['file'])


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.model = checks.read_yaml(COMPONENT / 'compose.yaml')

    def test_the_manifest_passes_the_rules_it_ships_under(self):
        self.assertEqual([], checks.check_model(self.model, COMPONENT))
        self.assertEqual([], checks.check_credential_files(self.model))

    def test_neither_service_publishes_a_host_port(self):
        """Design item 6: HOST_PUBLISHED_SERVICES stays as it is, so this is the guard for that."""
        for name, service in self.model['services'].items():
            with self.subTest(service=name):
                self.assertEqual([], service.get('ports', []))
                self.assertNotIn(name, checks.HOST_PUBLISHED_SERVICES)

    def test_both_images_are_required_variables_and_neither_pulls_at_boot(self):
        for name in ('gatus', 'detector'):
            service = self.model['services'][name]
            with self.subTest(service=name):
                self.assertTrue(checks.IMAGE_VARIABLE.fullmatch(service['image']))
                self.assertEqual('never', service['pull_policy'])
                self.assertTrue(service['read_only'])
                self.assertEqual(['ALL'], service['cap_drop'])

    def test_the_engine_states_the_architecture_its_digest_belongs_to(self):
        self.assertEqual('linux/amd64', self.model['services']['gatus']['platform'])
        self.assertEqual('never', self.model['services']['gatus']['pull_policy'])

    def test_the_detector_carries_a_healthcheck_whose_bound_comes_from_the_window(self):
        healthcheck = self.model['services']['detector']['healthcheck']
        test = ' '.join(healthcheck['test'])
        self.assertIn('LO_DETECTION_WINDOW_SECONDS', test,
                      'the staleness bound is derived at run time, so it cannot drift from the worker')
        self.assertIn('max(3*w,60)', test.replace(' ', ''))
        self.assertIn('LO_DETECTION_CURSOR', test)
        for key in ('interval', 'timeout', 'retries', 'start_period'):
            self.assertIn(key, healthcheck)

    def test_the_detector_healthcheck_actually_runs_and_its_bound_is_the_windows(self):
        """Execute the manifest's own probe rather than reading it.

        `docs/CONTRACTS.md` §6 is blunt that a static YAML read establishes nothing about behaviour, and
        a healthcheck nobody executed is exactly the kind of promise that rots: this one is a Python
        fragment that recomputes its staleness bound from `LO_DETECTION_WINDOW_SECONDS` at run time, so
        the arithmetic is checked the only way that means anything — by running it against a cursor file
        whose mtime is known. Offline, no container: `sys.executable` on a temp file.
        """
        program = ' '.join(self.model['services']['detector']['healthcheck']['test'][3:])
        import subprocess
        import time

        def exit_code(cursor_age: float, window: str, missing: bool = False) -> int:
            with tempfile.TemporaryDirectory() as directory:
                cursor = Path(directory) / 'cursor.json'
                if not missing:
                    cursor.write_text('{}', encoding='utf-8')
                    stamp = time.time() - cursor_age
                    os.utime(cursor, (stamp, stamp))
                # Inherit, then override: a stripped environment is what makes a child interpreter hang
                # on Windows, and a hang in a test suite is worse than a failure. The bound is the same
                # reason — this fragment does file arithmetic and must come back in milliseconds.
                environment = {**os.environ, 'LO_DETECTION_CURSOR': str(cursor),
                               'LO_DETECTION_WINDOW_SECONDS': window}
                try:
                    return subprocess.run([sys.executable, '-B', '-c', program], env=environment,
                                          capture_output=True, timeout=30).returncode
                except subprocess.TimeoutExpired as exc:
                    raise AssertionError(f'the healthcheck probe hung for {window}s window: {exc}') from exc

        # bound = max(3 * window, 60): 60 s at the default, 3 h at the top of the band.
        for window, age, expected in (('5', 30, 0), ('5', 61, 1), ('60', 179, 0), ('60', 200, 1),
                                      ('3600', 10_799, 0), ('3600', 10_801, 1)):
            with self.subTest(window=window, age=age):
                self.assertEqual(expected, exit_code(age, window),
                                 '0 means healthy; the bound must move with the window, not with the file')
        with self.subTest(case='no cursor file yet'):
            self.assertEqual(1, exit_code(0, '5', missing=True),
                             'a detector that has never closed a window is not healthy')

    def test_a_window_the_worker_would_refuse_makes_the_probe_fail_too(self):
        """Both ends of one misconfiguration must say the same thing: `int()` raising is the same answer
        the worker gives by refusing to start, so no operator sees a healthy container that is dead."""
        import subprocess
        program = ' '.join(self.model['services']['detector']['healthcheck']['test'][3:])
        environment = {**os.environ, 'LO_DETECTION_CURSOR': 'unused.json',
                       'LO_DETECTION_WINDOW_SECONDS': '30s'}
        self.assertEqual(1, subprocess.run([sys.executable, '-B', '-c', program], env=environment,
                                           capture_output=True, timeout=30).returncode)

    def test_the_engine_has_no_healthcheck_and_the_reason_is_written_down(self):
        """Not laziness: the pinned image is `FROM scratch`, so nothing exists to execute."""
        self.assertNotIn('healthcheck', self.model['services']['gatus'])
        compose = (COMPONENT / 'compose.yaml').read_text(encoding='utf-8')
        self.assertIn('scratch', compose)
        self.assertIn('coverage', compose, 'where engine liveness is decided instead, in prose')

    def test_every_credential_is_a_mounted_file_the_service_declares(self):
        for name, expected in (('detector', ['gatus-token', 'detector-producer-token']),
                               ('gatus', [])):
            with self.subTest(service=name):
                self.assertEqual(sorted(expected), sorted(checks.declared_secret_names(
                    self.model['services'][name])))
        environment = checks.compose_environment(self.model['services']['detector'])
        self.assertEqual('/run/secrets/gatus-token', environment['LO_GATUS_TOKEN_FILE'])
        self.assertNotIn('LO_GATUS_TOKEN', environment, 'a value in the environment is the secret files defect')
        for secret in ('gatus-token', 'detector-producer-token'):
            self.assertIn(secret, self.model['secrets'])

    def test_the_detector_reads_its_own_producer_credential_and_never_the_runner_s(self):
        """The manifest's secret sources, pinned: one credential row authenticates one identity.

        The detector posts under the identity its RULE document names (`detection_worker.tick()` sends
        `source=rule['source']`, and `local_observe/platform/state.py` refuses an event whose `source`
        is not the identity the token authenticated as — 'Source identity differs from authenticated
        producer'). The manifest used to mount `${LO_PRODUCER_TOKEN_FILE}` here, which is the Sigma
        runner's host file and the Sigma row's identity, so the shipped shape was a producer that polls,
        judges and is refused forever . The pin is on the `secrets:` SOURCE, not the container-side name:
        `read_credential('LO_PRODUCER_TOKEN')` is what the worker reads and that module belongs to
        another agent, so the host file is the half this component owns.
        """
        sources = {name: str((entry or {}).get('file')) for name, entry in self.model['secrets'].items()}
        self.assertRegex(sources['detector-producer-token'],
                         r'^\$\{LO_DETECTOR_PRODUCER_TOKEN_FILE:\?.+\}$',
                         'the detector must read a credential file of its own')
        self.assertNotIn('${LO_PRODUCER_TOKEN_FILE', ' '.join(sources.values()),
                         "mounting the Sigma runner's token under the rule's identity is the dedicated detector credential")
        self.assertEqual('/run/secrets/detector-producer-token',
                         checks.compose_environment(self.model['services']['detector'])['LO_PRODUCER_TOKEN_FILE'],
                         'the container path is what read_credential resolves; it does not move')
        # The engine's own credential is a different secret and stays where it was.
        self.assertRegex(sources['gatus-token'], r'^\$\{LO_GATUS_TOKEN_FILE:\?.+\}$')

    def test_the_variable_names_the_stage_already_used_survive_the_move(self):
        """The brief keeps the stage bootable by an environment file nobody has to edit.

        `LO_DETECTOR_PRODUCER_TOKEN_FILE` joins the list on 2026-09-10 : it is the host file
        this detector's producer credential is read from, and the stage driver has to name it too — the
        rule it stages (`examples/platform/availability.yaml`, `source: stage-detector`) already matches
        the `stage-detector` row the driver mints, so the stage's identity was never wrong, only the
        variable carrying it.
        """
        body = (COMPONENT / 'compose.yaml').read_text(encoding='utf-8')
        for variable in ('LO_GATUS_IMAGE', 'LO_GATUS_CONFIG', 'LO_GATUS_URL', 'LO_GATUS_TOKEN_FILE',
                         'LO_DETECTION_RULE_DIR', 'LO_DETECTION_CURSOR', 'LO_DETECTION_RULE',
                         'LO_PLATFORM_INDEX_DIR', 'LO_PRODUCER_TOKEN_FILE',
                         'LO_DETECTOR_PRODUCER_TOKEN_FILE', 'LO_PLATFORM_IMAGE'):
            with self.subTest(variable=variable):
                self.assertIn(variable, body)

    def test_persistence_is_project_scoped_and_logs_are_bounded(self):
        self.assertEqual({'gatus-data', 'detector-data'}, set(self.model['volumes']))
        for name, volume in self.model['volumes'].items():
            self.assertFalse(volume and any(key in volume for key in ('name', 'external', 'driver_opts')),
                             name)
        for name, service in self.model['services'].items():
            with self.subTest(service=name):
                self.assertEqual('json-file', service['logging']['driver'])


class GatusConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = checks.read_yaml(COMPONENT / 'config.yaml')

    def test_the_status_api_is_protected_and_the_protector_holds_no_real_credential(self):
        security = self.config.get('security') or {}
        basic = security.get('basic') or {}
        self.assertTrue(basic.get('username'), 'an empty username is an invalid block: Gatus will not boot')
        self.assertTrue(basic.get('password-bcrypt-base64'))
        for value in basic.values():
            self.assertIn('RENDER-ME', value,
                          'a committed value that could work is a credential in the tree')

    def test_the_shipped_marker_cannot_be_decoded_so_an_unrendered_file_cannot_boot(self):
        """The claim in `config.yaml` is that an unrendered copy crash-loops rather than serves.

        That is a claim about bytes, so it is checked on bytes: Gatus decodes this field with Go's
        `base64.URLEncoding`, a strict decoder over the `-`/`_` alphabet, and `api/api.go` panics on
        the error it returns. The nearest equivalent in the standard library is `b64decode` with
        `altchars` and `validate=True`. The self-test half matters more than the assertion: upstream's
        own worked example must decode under the same call, or all this proves is that my decoder is
        wrong. Source read at the pinned tag (scratch/v5360_security_config.go, scratch/README
        "Basic Authentication"), never run.
        """
        def url_strict(text: str) -> bytes:
            return base64.b64decode(text, altchars=b'-_', validate=True)

        marker = self.config['security']['basic']['password-bcrypt-base64']
        with self.assertRaises(binascii.Error,
                               msg='a marker that decodes is a marker that boots: the credential would '
                                   'be missing only in the sense that matters least'):
            url_strict(marker)
        self.assertEqual(b'$2a$10$',
                         url_strict('JDJhJDEwJHRiMnRFakxWazZLdXBzRERQazB1TE8vckRLY05Yb1hSdnoxWU0yQ1FaYXZ'
                                    'RSW1McmladDYu')[:7],
                         'the reference hash from upstream\'s table must decode under the same rule')

    def test_no_variable_expansion_reaches_a_value_of_the_shipped_document(self):
        """`os.ExpandEnv` turns an unset name into an empty string, and empty required fields here mean
        either a boot failure or — worse, for `security` — a block Gatus ignores. The prose above the
        document may name the mechanism; no parsed value may use it.
        """

        def values(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    yield from values(key)
                    yield from values(item)
            elif isinstance(node, list):
                for item in node:
                    yield from values(item)
            elif isinstance(node, str):
                yield node
        self.assertEqual([], sorted(text for text in values(self.config) if '$' in text))

    def test_exactly_one_target_is_shipped_and_it_names_a_service_in_every_composition(self):
        endpoint = self.config['endpoints'][0]
        self.assertEqual(1, len(self.config['endpoints']),
                         'the committed config proves the mechanism, it does not sweep a range')
        # The URL's authority must name the `platform` service, the one declared service present in
        # every composition that includes this component (examples/demo has no platform, and includes
        # no synthetics either).
        authority = endpoint['url'].split('//', 1)[1].split('/', 1)[0]
        self.assertEqual('platform:8002', authority)

    def test_the_derived_endpoint_key_is_the_one_the_manifest_default_calls(self):
        endpoint = self.config['endpoints'][0]
        key = derived_key(endpoint.get('group', ''), endpoint['name'])
        self.assertEqual('lo_platform-http', key)
        default = DEFAULTED_VARIABLE.findall((COMPONENT / 'compose.yaml').read_text(encoding='utf-8'))
        urls = [value for name, value in default if name == 'LO_GATUS_URL']
        self.assertEqual(1, len(urls))
        self.assertIn('/api/v1/endpoints/' + key + '/statuses', urls[0])

    def test_the_probe_interval_is_inside_the_freshness_bound_the_product_rule_default_uses(self):
        endpoint = self.config['endpoints'][0]
        seconds = int(re.fullmatch(r'(\d+)s', endpoint['interval']).group(1))
        self.assertLessEqual(seconds * 3, 120, 'max_age_seconds defaults to 120 in detections.evaluate; '
                                              'an interval above a third of it makes coverage flap')

    def test_the_expiry_stages_are_declared_with_the_named_gatus_feature(self):
        body = (COMPONENT / 'config.yaml').read_text(encoding='utf-8')
        for stage in ('720h', '336h', '24h'):
            with self.subTest(stage=stage):
                self.assertIn(stage, body)
        self.assertIn('[CERTIFICATE_EXPIRATION]', body)
        self.assertIn('NOT SHIPPED', body, 'zero real targets means the stages are a declaration')
        self.assertIn('[DNS_RCODE]', body)

    def test_the_sqlite_history_stays_on_the_volume_the_backup_recipe_names(self):
        self.assertEqual('sqlite', self.config['storage']['type'])
        self.assertEqual('/data/gatus.db', self.config['storage']['path'])
        self.assertIn('gatus-data:/data', [str(v) for v in self.model_services()['gatus']['volumes']])

    @staticmethod
    def model_services():
        return checks.read_yaml(COMPONENT / 'compose.yaml')['services']


class ExampleWiringTests(unittest.TestCase):
    def test_both_examples_resolve_the_two_services_and_their_templates_agree(self):
        for name in ('examples/full/compose.yaml', 'examples/platform/compose.yaml'):
            with self.subTest(example=name):
                example = ROOT / name
                services, errors = checks.example_services(ROOT, example)
                self.assertEqual([], errors)
                self.assertIn('gatus', services)
                self.assertIn('detector', services)
                required, defaulted = set(), set()
                body = (COMPONENT / 'compose.yaml').read_text(encoding='utf-8')
                required.update(match.group(1) for match in REQUIRED_VARIABLE.finditer(body))
                defaulted.update(match.group(1) for match in DEFAULTED_VARIABLE.finditer(body))
                keys = set(template_values(example))
                self.assertEqual(sorted(required - keys), [], 'required variable with no template line')

    def test_the_stage_fragment_no_longer_defines_the_moved_services_or_their_state(self):
        fragment = checks.read_yaml(ROOT / 'examples/platform/staging.compose.yaml')
        self.assertEqual({'platform', 'demo-target', 'notification-sink'}, set(fragment['services']))
        self.assertEqual({'notification-data'}, set(fragment['volumes']))
        self.assertEqual({'notify-token'}, set(fragment['secrets']))

    def test_the_docs_row_stops_saying_there_is_no_component_directory(self):
        row = next(line for line in (ROOT / 'docs' / 'COMPONENTS.md').read_text(encoding='utf-8').splitlines()
                   if line.startswith('| synthetics |'))
        self.assertNotIn('no component directory', row)
        self.assertIn('components/control/synthetics', row)
        self.assertIn('No synthetic coverage', row)


if __name__ == '__main__':
    unittest.main()
