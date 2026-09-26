"""The `crowdsec` component: its artefacts, its manifest, its pin, and the shape of its example.

crowdsec turns a line in `docs/COMPONENTS.md` §3 into a component directory, which means everything a
component owes can be refused statically — including the thing this component is mostly made of, which
is an absence: no bouncer, no published port, no host network, no write path. Absences are exactly what
 rots silently, so they are pinned here rather than relied on.

Two limits this file states rather than hides:

* Nothing in `EXAMPLE_MANIFESTS` includes this component, so the plain `check_foundation.py` run never
  opens it. That is the *point* of an optional integration, and the hole it would leave is closed by
  running the same rules over the manifest and the example directly (`ModelGateTests`,
  `ExampleCompositionTests`) — see PublicationTests for the residual the suite cannot reach: an
  operator's own bouncer overlay.
* Nothing here starts a container. The runtime half is `components/control/crowdsec/conformance.md`, and
  almost every row of it says `not-run`.
"""
import contextlib
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks
from local_observe.platform import crowdsec

COMPONENT = ROOT / 'components' / 'control' / 'crowdsec'
EXAMPLE = ROOT / 'examples' / 'crowdsec'
PACKAGE = ROOT / 'local_observe' / 'platform' / 'crowdsec.py'
REQUIRED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):\?")
DEFAULTED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]*)\}")
DIGEST = re.compile(r'^sha256:[a-f0-9]{64}$')
#: The host-published set as measured on 2026-09-09, re-pinned so no row widens it silently. `crowdsec`
#: adds no name to it (tests/test_ai_component.py pins the same tuple from the other direction). The
#: eighth name arrived with MCP component (`mcp`, loopback-only, argued in the comment above the tuple).
PUBLISHED = ('signoz', 'lo-front-door', 'platform', 'inventory', 'dagu', 'healthchecks', 'homepage',
             'mcp')


def template_values():
    """The example's own `.env.example` as a mapping, for rendering `${VAR:?}`/`${VAR:-x}` lines."""
    body = (EXAMPLE / '.env.example').read_text(encoding='utf-8')
    return dict(re.findall(r"(?m)^([A-Z0-9_]+)=(.*)$", body))


def example_variables():
    """(required names, defaulted {name: shipped value}) across the example and everything it includes."""
    required, defaulted = set(), {}
    files = [EXAMPLE / 'compose.yaml']
    for entry in checks.read_yaml(EXAMPLE / 'compose.yaml').get('include') or []:
        files.extend(checks.include_entry(entry, EXAMPLE)[0])
    for path in files:
        body = path.read_text(encoding='utf-8')
        required.update(match.group(1) for match in REQUIRED_VARIABLE.finditer(body))
        for match in DEFAULTED_VARIABLE.finditer(body):
            defaulted[match.group(1)] = match.group(2)
    return required, defaulted


def bearer_line():
    """The shipped notification file's `Authorization` value, read as YAML rather than as text.

    Reading the document instead of grepping it matters: half the file is prose about the credential,
    and a test that counts the word "Authorization" counts the warnings too.
    """
    document = checks.read_yaml(EXAMPLE / 'http-notification.yaml')
    return document['headers']['Authorization']


class ShippedArtefactsTests(unittest.TestCase):
    """quality bar's five artefacts, plus the two files that only this component has."""

    def test_the_five_artefacts_the_manifest_and_the_two_fragments_are_all_present(self):
        for name in ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md', 'versions.json',
                     'compose.yaml', 'actions.example.json'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_example_ships_the_operator_shapes_it_tells_people_to_render(self):
        """README.md names four files; a shape it names and does not ship is a documentation bug."""
        for name in ('compose.yaml', '.env.example', 'README.md', 'profiles.yaml',
                     'http-notification.yaml', 'intake-rules.json'):
            with self.subTest(file=name):
                self.assertTrue((EXAMPLE / name).is_file(), f'{name} is missing')
        readme = (EXAMPLE / 'README.md').read_text(encoding='utf-8')
        for name in ('profiles.yaml', 'http-notification.yaml', 'intake-rules.json'):
            self.assertIn(name, readme, f'{name} exists but README.md never names it')

    def test_both_json_fragments_parse_and_the_actions_one_is_an_object_of_definitions(self):
        actions = json.loads((COMPONENT / 'actions.example.json').read_text(encoding='utf-8'))
        self.assertEqual(sorted(actions), ['crowdsec-decision-apply', 'crowdsec-decision-remove'])
        for name, definition in actions.items():
            with self.subTest(action=name):
                self.assertEqual(sorted(set(definition)),
                                 ['parameters', 'protected_destinations', 'version'])
        json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))


class ModelGateTests(unittest.TestCase):
    """The rules `check_example` would run — run directly, because no example includes this manifest."""

    def setUp(self):
        self.model = checks.read_yaml(COMPONENT / 'compose.yaml')

    def test_the_manifest_passes_the_model_rules_the_gate_uses(self):
        self.assertEqual(checks.check_model(self.model, COMPONENT), [])
        self.assertEqual(checks.check_credential_files(self.model), [])

    def test_the_manifest_declares_one_service_and_no_bouncer(self):
        self.assertEqual(list(self.model['services']), ['crowdsec'])
        crowdsec = self.model['services']['crowdsec']
        self.assertFalse(crowdsec.get('privileged'), 'check_model refuses this on purpose')
        self.assertNotEqual(crowdsec.get('network_mode'), 'host')
        self.assertNotIn('cap_add', crowdsec)

    def test_the_two_persisted_directories_upstream_requires_are_both_volumes(self):
        """The image refuses to start without `/var/lib/crowdsec/data` mounted (README, v1.8.1)."""
        mounts = ' '.join(str(item) for item in self.model['services']['crowdsec']['volumes'])
        for target in ('/var/lib/crowdsec/data', '/etc/crowdsec'):
            self.assertIn(target, mounts, f'{target} is not persisted, so an upgrade loses it')

    def test_no_credential_name_the_gate_polices_appears_as_an_environment_key(self):
        """`LO_*_(TOKEN|PASSWORD|SECRET)` may only ever arrive as a `*_FILE` path."""
        environment = checks.compose_environment(self.model['services']['crowdsec'])
        for key, value in environment.items():
            with self.subTest(variable=key):
                self.assertNotRegex(key, r'_(TOKEN|PASSWORD|SECRET)$')
                self.assertNotRegex(str(value), r'_(TOKEN|PASSWORD|SECRET)\}')


class PublicationTests(unittest.TestCase):
    """The absence that carries the row's honesty: nothing is reachable from the host."""

    def test_the_service_publishes_no_port_and_the_gate_list_is_untouched(self):
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertNotIn('ports', model['services']['crowdsec'])
        self.assertNotIn('crowdsec', checks.HOST_PUBLISHED_SERVICES)
        self.assertEqual(checks.HOST_PUBLISHED_SERVICES, PUBLISHED)

    def test_the_example_is_not_in_the_shipped_manifest_list_and_says_so(self):
        """Optional means not selected by default; the README must then say how to gate it at all."""
        self.assertNotIn('examples/crowdsec/compose.yaml', checks.EXAMPLE_MANIFESTS)
        self.assertIn('--compose examples/crowdsec/compose.yaml',
                      (EXAMPLE / 'compose.yaml').read_text(encoding='utf-8') +
                      (EXAMPLE / '.env.example').read_text(encoding='utf-8') +
                      (EXAMPLE / 'README.md').read_text(encoding='utf-8'))


class ExampleCompositionTests(unittest.TestCase):
    """The composition an operator pastes, gated the way their own top-level file would be."""

    def test_the_example_gates_clean_through_its_include_entry(self):
        self.assertEqual(checks.check_foundation(ROOT, compose=[str(EXAMPLE / 'compose.yaml')]), [])

    def test_env_template_covers_every_required_variable_and_nothing_else(self):
        required, defaulted = example_variables()
        keys = set(template_values())
        self.assertEqual(sorted(required - keys), [], 'required variable with no template line')
        self.assertEqual(sorted(keys - required - set(defaulted)), [], 'template line no manifest reads')
        self.assertTrue(required, 'the manifest demands nothing, which is how a pin goes missing')

    def test_the_two_defaulted_variables_default_to_the_safe_reading(self):
        """community blocklist dependency: the blocklist opt-in must be off in the file an operator copies, not on."""
        _, defaulted = example_variables()
        self.assertEqual(defaulted.get('LO_CROWDSEC_CAPI_DISABLED'), 'true')
        self.assertEqual(defaulted.get('LO_CROWDSEC_COLLECTIONS'), 'crowdsecurity/linux')

    def test_the_notification_shape_names_the_intake_route_and_carries_no_credential_value(self):
        body = (EXAMPLE / 'http-notification.yaml').read_text(encoding='utf-8')
        self.assertIn('http://platform:8002/v1/intake/crowdsec', body)
        bearer = bearer_line()
        self.assertTrue(bearer.startswith('Bearer '), f'the header must be a bearer pair, reads {bearer!r}')
        self.assertIn('REPLACE', bearer, 'a shipped file must hold a placeholder, never a token')
        self.assertNotRegex(bearer, r'[A-Za-z0-9]{24,}', 'a 24+ character run reads like a real key')

    def test_the_intake_rules_shape_is_a_document_the_normaliser_accepts(self):
        document = json.loads((EXAMPLE / 'intake-rules.json').read_text(encoding='utf-8'))
        rules = crowdsec.validate_rules(document)
        self.assertEqual(list(rules), ['crowdsec'])
        self.assertEqual({row['kind'] for row in rules['crowdsec'].values()}, {'security'})

    def test_the_profile_shape_keeps_crowdsec_from_remediating_on_its_own(self):
        """`simulated: true` is auto-block authority's load-bearing line, and it sits on the decision, not the profile.

        Two upstream facts make this test worth having, both read at v1.8.1: `pkg/csconfig/profiles.go`
        decodes `profiles.yaml` with `dec.KnownFields(true)`, so a key outside `ProfileCfg` is not ignored
        — the Local API refuses to start; and `models.Decision` is where `Simulated` lives, which
        `pkg/csprofiles/csprofiles.go` copies onto every decision the profile emits. A profile-level
        `simulated:` therefore looks protective and is a crash, and this shape is the one that is both
        honest and loadable.
        """
        body = checks.read_yaml(EXAMPLE / 'profiles.yaml')
        declared = {'name', 'debug', 'filters', 'decisions', 'duration_expr', 'on_success', 'on_failure',
                    'on_error', 'notifications'}
        self.assertEqual(set(body) - declared, set(),
                         'a key ProfileCfg does not declare stops the Local API at start-up')
        self.assertNotIn('simulated', body, 'the profile has no simulated flag; the decision does')
        self.assertTrue(body['decisions'], 'a profile with no decisions is not the shape this file claims')
        for row in body['decisions']:
            self.assertIs(row.get('simulated'), True,
                          'a decision without simulated is one a bouncer would apply unapproved')
            self.assertLessEqual(set(row), {'type', 'duration', 'simulated', 'scope', 'value'},
                                 'models.Decision carries no other key at the pinned tag')
        self.assertEqual([row['type'] for row in body['decisions']], ['ban'])
        self.assertEqual(body['notifications'], ['http_default'],
                         'the profile selects notifications by name, and only by name')

    def test_the_shipped_notification_template_wraps_the_array_the_transport_refuses(self):
        """The one seam between upstream's default body and this platform's object-only POST handler.

        `cmd/notification-http/http.yaml` at v1.8.1 ships `format: |` + `{{.|toJson}}`, which renders a
        bare JSON array, and `api.py` answers 400 `Expected a JSON object body` to a body that is not an
        object. The example must therefore NOT be upstream's default file, and the difference is exactly
        one wrapper: pin it, because an operator "simplifying" this line back to upstream's default
        silences the intake path with a 400 the plugin only shows in its own log.
        """
        rendered = checks.read_yaml(EXAMPLE / 'http-notification.yaml')['format'].strip()
        self.assertTrue(rendered.startswith('{"alerts": '), f'the array must arrive wrapped, reads {rendered!r}')
        self.assertTrue(rendered.endswith('{{.|toJson}}}'), 'the alert list itself stays upstream-rendered')
        self.assertEqual(json.loads(rendered.replace('{{.|toJson}}', '[]')), {crowdsec.ALERTS_KEY: []})

    def test_the_intake_rule_shape_declares_a_scenario_the_adapter_can_match(self):
        """The shipped rules file must name a scenario CrowdSec can actually emit, not a made-up one."""
        document = json.loads((EXAMPLE / 'intake-rules.json').read_text(encoding='utf-8'))
        rows = crowdsec.validate_rules(document)['crowdsec']
        self.assertIn('crowdsecurity/ssh-bf', rows, 'threat detection engine kept the ssh brute-force half, so name that one')


class PinTests(unittest.TestCase):
    """The pin file is the component's evidence. These are checks on the evidence, not on the value."""

    def setUp(self):
        self.pin = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))

    def test_the_status_is_experimental_and_the_run_claim_is_absent(self):
        self.assertEqual(self.pin['status'], 'experimental')
        self.assertIsNone(self.pin['verified_on'])
        self.assertIn('NOT RUN', self.pin['runtime_state'])

    def test_the_image_is_a_digest_and_never_a_moving_channel(self):
        self.assertRegex(self.pin['image'], r'^crowdsecurity/crowdsec@sha256:[a-f0-9]{64}$')
        self.assertNotIn(':latest', self.pin['image'])
        self.assertEqual(self.pin['image'].split('@')[1].removeprefix('sha256:'),
                         self.pin['digests']['value_used_by_LO_CROWDSEC_IMAGE'].removeprefix('sha256:'))

    def test_every_digest_is_a_digest_and_every_read_carries_a_date_and_a_url(self):
        for name, value in self.pin['digests'].items():
            if name.startswith('what_') or name.startswith('why_') or name == 'verified_by':
                continue
            with self.subTest(digest=name):
                self.assertRegex(value, DIGEST)
        self.assertRegex(self.pin['digest_provenance']['read_on'], r'^\d{4}-\d{2}-\d{2}$')
        self.assertTrue(self.pin['digest_provenance']['registry_url'].startswith('https://'))
        for key in ('method', 'resolved_with', 'tags_read'):
            self.assertIn(key, self.pin['digest_provenance'])

    def test_the_release_names_the_licence_and_where_the_licence_was_read(self):
        self.assertEqual(self.pin['release']['license'], 'MIT')
        self.assertIn('spdx_id', self.pin['release']['license_verified_by'])
        self.assertEqual(self.pin['release']['tag'], 'v1.8.1')

    def test_the_unverified_list_exists_and_names_the_bouncer_and_the_write_endpoints(self):
        """A pin that admits what it did not check is the difference between evidence and folklore."""
        joined = ' '.join(self.pin['unverified'])
        self.assertTrue(self.pin['unverified'])
        for topic in ('bouncer', 'create', 'collection', 'DISABLE_ONLINE_API', 'read_only'):
            self.assertIn(topic, joined, f'the UNVERIFIED list is missing {topic}')

    def test_no_bouncer_image_is_pinned_anywhere_and_is_named_only_where_it_is_refused(self):
        """The bouncer is documented, never pinned: naming a repository in a manifest implies a pull.

        `versions.json` does name it, in exactly one place and for one reason — the UNVERIFIED list
        records that its container coordinates were measured NOT to be `crowdsecurity/cs-firewall-bouncer`
        (404 from the tags API, 2026-09-09). That is the honest home of the name, and this test keeps it
        there rather than letting it migrate into an `image` key on a later edit.
        """
        self.assertNotIn('cs-firewall-bouncer', (COMPONENT / 'compose.yaml').read_text(encoding='utf-8'))
        pin = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.assertNotIn('cs-firewall-bouncer', pin['image'])
        named = sorted(key for key, value in pin.items()
                       if 'cs-firewall-bouncer' in json.dumps(value))
        self.assertEqual(named, ['digest_provenance', 'unverified'],
                         'the bouncer may be named only where this file says it was NOT verified')
        self.assertIn('cs-firewall-bouncer', ' '.join(pin['unverified']))

    def test_the_platform_architecture_the_manifest_states_is_the_one_the_digest_is(self):
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertEqual(model['services']['crowdsec']['platform'], 'linux/amd64')
        self.assertTrue(self.pin['platform'].startswith('linux/amd64'))


class PrivacyTests(unittest.TestCase):
    """The gate's privacy walk covers `components/` and `examples/`; this names the list directly."""

    def test_no_estate_token_appears_in_the_component_or_the_example(self):
        for base in (COMPONENT, EXAMPLE):
            for path in sorted(base.rglob('*')):
                if not path.is_file():
                    continue
                body = path.read_text(encoding='utf-8')
                hits = [token for token in checks.BANNED_TOKENS if token in body]
                with self.subTest(path=path.relative_to(ROOT).as_posix()):
                    self.assertEqual(hits, [])

    def test_the_shipped_notification_shape_holds_a_placeholder_rather_than_a_token(self):
        self.assertIn('REPLACE', bearer_line(), 'a bearer line must be a placeholder')


class SurfaceTests(unittest.TestCase):
    """What this component must not have grown by the time someone "finishes" it."""

    def test_the_package_still_ships_no_second_emitter(self):
        """Design item 2: alerts reach the platform through event intake and nowhere else."""
        source = PACKAGE.read_text(encoding='utf-8')
        for forbidden in ('urlopen', 'urllib.request.Request', '/v1/events', 'requests.post'):
            self.assertNotIn(forbidden, source,
                             f'crowdsec.py names {forbidden}: alerts must go through intake.prepare')

    def test_the_module_imports_no_optional_package(self):
        """The base tier of `docs/testing-standards.md` installs stdlib + PyYAML + jsonschema only."""
        import ast
        tree = ast.parse(PACKAGE.read_text(encoding='utf-8'), filename=str(PACKAGE))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names.add(node.module)
        self.assertLessEqual(names, {'collections.abc', 'datetime', 'ipaddress', 'json', 'math',
                                     'pathlib', 're', 'sys', 'typing', 'urllib.parse',
                                     'local_observe.credentials', 'local_observe.http',
                                     'local_observe.inventory.validation', 'local_observe.log'})


class CommandLineTests(unittest.TestCase):
    """`python -B -m local_observe.platform.crowdsec`, the way `conformance.md` tells an operator to run it.

    A documented command that exits 1 on a good file is worse than no command: the operator reads the
    failure as "my policy is dangerous" and edits the file until the tool is quiet. The first build of
    this surface did exactly that to `--check-rules`, because `validate_rules` returns a mapping of
    parsed rules where `validate_action_document` returns a list of problems, and one adapter line was
    missing. These four rows are that lesson, kept as exit codes.
    """

    def run_check(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = crowdsec.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_both_shipped_documents_pass_and_say_so_once(self):
        for flag, path in (('--check-actions', COMPONENT / 'actions.example.json'),
                           ('--check-rules', EXAMPLE / 'intake-rules.json')):
            with self.subTest(flag=flag):
                code, out, err = self.run_check(flag, str(path))
                self.assertEqual((code, err), (0, ''), 'a sound file must not cost the operator a warning')
                self.assertEqual(out.strip(), f'{path}: ok')

    def test_a_damaged_policy_file_exits_1_and_names_the_problem(self):
        with tempfile.TemporaryDirectory() as temp:
            broken = Path(temp) / 'policy.json'
            broken.write_text(json.dumps({'crowdsec-decision-apply': {'version': '1',
                                                                      'parameters': {}}}),
                              encoding='utf-8')
            code, _, err = self.run_check('--check-actions', str(broken))
        self.assertEqual(code, 1)
        self.assertIn('crowdsec-decision-apply', err)

    def test_a_rules_document_the_vocabulary_refuses_exits_1_rather_than_printing_its_rows(self):
        """The regression itself: a parsed mapping used to be printed as if it were a list of errors."""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'rules.json'
            path.write_text(json.dumps({'schema_version': 1, 'sources': {'crowdsec': {
                'crowdsecurity/ssh-bf': {'rule_id': 'crowdsec.ssh-brute-force', 'kind': 'availability',
                                         'window_seconds': 120, 'sample_field': 'metric:events_count'}}}}),
                            encoding='utf-8')
            code, out, err = self.run_check('--check-rules', str(path))
        self.assertEqual(code, 1)
        self.assertEqual(out, '')
        self.assertIn('closed vocabulary', err)

    def test_the_command_never_reads_a_directory_a_huge_file_or_a_bad_flag(self):
        self.assertEqual(self.run_check('--check-rules', str(EXAMPLE))[0], 1)
        self.assertEqual(self.run_check('--check-rules')[0], 2)
        self.assertEqual(self.run_check('--check-everything', str(EXAMPLE / 'intake-rules.json'))[0], 2)
        with tempfile.TemporaryDirectory() as temp:
            huge = Path(temp) / 'huge.json'
            huge.write_text('[' * (crowdsec.MAX_ACTION_DOCUMENT_BYTES + 1), encoding='utf-8')
            self.assertEqual(self.run_check('--check-rules', str(huge))[0], 1)


if __name__ == '__main__':
    unittest.main()
