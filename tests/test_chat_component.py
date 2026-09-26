"""Structural tests for the `chat` component: the manifest, the absence, and the pin's own unknowns.

chat integration's deliverable is a component directory for a surface that has never run, which makes the honest
question "what can a test possibly say about it?" The answer this file gives is the four things that do
not need a container:

* the manifest obeys the same model rules every shipped Compose file obeys — and it needs its own
  test for that, because it is in **no** example, so `check_example` never reaches it (the same
  arrangement `tests/test_ai_component.py` records for `ai`);
* the two properties the surface cannot be trusted to keep by itself are refused in the tree rather
  than in prose: telemetry is off in the exact string form the pinned build checks, and no
  auto-approval knob appears where a chat client could reach it;
* the component is absent from every default bring-up, which is `docs/COMPONENTS.md` §4's "no hidden
  prerequisite" and the row's `If disabled` clause expressed as files;
* `versions.json` states what it did not verify, so a reader cannot mistake a resolvable digest for a
  run image.

integration validation's four chat checks and the round trip are a separate file,
`tests/test_chat_approval_separation.py`.
"""
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks

COMPONENT = ROOT / 'components' / 'control' / 'chat'
MANIFEST = COMPONENT / 'compose.yaml'
# The one loopback publication this row has not enabled (CONTRACT.md section 3). The test asserts the
# name and the port so a reviewer applying the two-line widening sees exactly what was promised here.
INTENDED_PUBLICATION = '127.0.0.1:${LO_CHAT_PORT:-18101}:3001'
# AnythingLLM's own variable names (not LO_*), each with the reason it must not appear in a shipped
# manifest. The gate cannot police them — check_credential_files only matches product names — so the
# discipline is a test or it is nothing.
FORBIDDEN_ENV = ('AGENT_AUTO_APPROVED_SKILLS', 'MCP_NO_COOLDOWN', 'SIMPLE_SSO_ENABLED',
                 'AUTH_TOKEN', 'OPEN_AI_KEY', 'ANTHROPIC_API_KEY', 'GEMINI_API_KEY')
# Internal forge shorthand: a card/issue/PR number from a tracker a reader of this repository cannot
# reach, whose numbering is that instance's own. Such a number carries no information outward and is
# the one citation class a shipped document can always replace — with the code or the test that proves
# the claim. Asserted about the shape, never about a specific number, so no private id is repeated.
FORGE_SHORTHAND = re.compile(r"\b(?:card|issue|pull request|PR) #\d+")


def model() -> dict:
    """The component manifest as the gate reads it, with no example merged in."""
    return checks.read_yaml(MANIFEST)


def environment() -> dict:
    """The chat service's rendered `environment` mapping, both Compose spellings accepted."""
    return checks.compose_environment(model()['services']['chat'])


class ShippedArtefactsTests(unittest.TestCase):
    def test_the_five_artefacts_and_the_manifest_are_all_present(self):
        """quality bar counts five artefacts per component; the row cannot be called built without them."""
        for name in ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md', 'versions.json',
                     'compose.yaml'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_manifest_passes_the_model_rules_the_gate_uses(self):
        """No example includes this file, so `check_example` never reaches it — this test does."""
        self.assertEqual(checks.check_model(model(), COMPONENT), [])
        self.assertEqual(checks.check_credential_files(model()), [])
        self.assertEqual(checks.check_delivery(model()), [],
                         'a chat surface must not acquire a delivery default by accident')

    def test_the_hardened_shape_the_gate_cannot_check_is_checked_here(self):
        """read_only, cap_drop, pull_policy and a bounded log: the four lines a host run cannot undo."""
        service = model()['services']['chat']
        self.assertEqual(service['pull_policy'], 'never',
                         'the pinned build migrates its own schema at start; a silent pull is a '
                         'silent migration')
        self.assertTrue(service['read_only'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertNotIn('cap_add', service, 'upstream adds SYS_ADMIN; this manifest takes the '
                                             'documented no-sandbox branch instead (CONTRACT.md)')
        self.assertEqual(service['security_opt'], ['no-new-privileges:true'])
        self.assertTrue(str(service['mem_limit']).startswith('${LO_CHAT_MEM_LIMIT:?'),
                        'an uncapped container on a 16 GB standard host is the failure this row '
                        'was called out for')
        self.assertLessEqual(service['pids_limit'], 256)
        self.assertEqual(service['logging']['driver'], 'json-file')

    def test_the_state_is_one_project_scoped_volume_and_the_rest_is_ephemeral(self):
        """backup.md's scope must be derivable from the manifest, or the recipe is fiction."""
        model_document = model()
        volumes = model_document['services']['chat']['volumes']
        self.assertEqual(volumes, ['chat-storage:/app/server/storage'])
        self.assertEqual(list(model_document['volumes']), ['chat-storage'])
        self.assertIsNone(model_document['volumes']['chat-storage'],
                          'project-scoped and un-nameable: no `name`, no `external`, no driver_opts')
        tmpfs = ' '.join(model_document['services']['chat']['tmpfs'])
        self.assertIn('/app/collector/hotdir', tmpfs)
        self.assertIn('/app/collector/outputs', tmpfs,
                      'the entrypoint always starts the collector, so its two directories need a '
                      'writable place that dies with the container')

    def test_the_settings_file_arrives_as_a_mounted_secret_at_the_path_dotenv_reads(self):
        """AnythingLLM has no `*_FILE` convention, so the whole file is the credential shape."""
        service = model()['services']['chat']
        self.assertEqual(service['secrets'], [{'source': 'chat-settings', 'target': '/app/server/.env'}])
        declared = model()['secrets']['chat-settings']
        self.assertTrue(str(declared['file']).startswith('${LO_CHAT_SETTINGS_FILE:?'))
        for name, value in environment().items():
            self.assertNotRegex(str(value), r'(?i)(sk-|api[_-]?key\s*=|Bearer [A-Za-z0-9])',
                                f'{name} looks like a literal credential in the container environment')

    def test_telemetry_is_off_in_the_exact_form_the_pinned_build_checks(self):
        """server/models/telemetry.js:50 returns null only when the value is the string "true"."""
        values = environment()
        self.assertEqual(values['DISABLE_TELEMETRY'], 'true')
        self.assertEqual(values['DISABLE_SWAGGER_DOCS'], 'true')
        self.assertEqual(values['STORAGE_DIR'], '/app/server/storage',
                         'the entrypoint warns and boots anyway without it, and "boots anyway" is '
                         'how a transcript is written somewhere nobody backs up')
        self.assertEqual(values['SERVER_PORT'], '3001',
                         'a literal, because the healthcheck probes that port by number')

    def test_the_transcript_knobs_that_exist_are_set_and_none_of_them_claims_to_stop_the_write(self):
        """CONTRACT.md section 7's honesty, pinned: hidden is not unwritten."""
        values = environment()
        self.assertEqual(values['DISABLE_VIEW_CHAT_HISTORY'], '1')
        self.assertEqual(values['WORKSPACE_DELETION_PROTECTION'], '1')
        self.assertEqual(values['AGENT_MAX_TOOL_CALLS'], '${LO_CHAT_MAX_TOOL_CALLS:-10}')
        # Whitespace-normalised, because the sentence is worth pinning and Markdown wraps it.
        contract = ' '.join((COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8').split())
        self.assertIn('No flag at the pinned commit stops the write', contract)

    def test_no_approval_or_credential_knob_reaches_the_container_environment(self):
        """AGENT_AUTO_APPROVED_SKILLS is quoted only as an absence, and upstream key names appear nowhere."""
        names = set(environment())
        for name in FORBIDDEN_ENV:
            with self.subTest(name=name):
                self.assertNotIn(name, names)
        body = MANIFEST.read_text(encoding='utf-8')
        # Named in the manifest *as a refusal* is fine; set in the environment block is not.
        self.assertGreaterEqual(body.count('AGENT_AUTO_APPROVED_SKILLS'), 1,
                               'the refusal must be written down, not merely absent')

    def test_the_surface_is_never_granted_approval_or_dispatch(self):
        """integration validation's "approval separation", read off the documents the operator follows."""
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        for refused in ('`execute_action`', 'actions/decision', 'role `executor` only',
                        'role `human` only'):
            with self.subTest(refused=refused):
                self.assertIn(refused, contract)
        self.assertIn('the action **stays `pending`**', contract,
                      'the callback half of the refusal is the subtle one and must be in prose too')

    def test_publication_is_commented_and_names_the_two_edits(self):
        """No port today, and the intended line is stated so the widening cannot be improvised."""
        service = model()['services']['chat']
        self.assertNotIn('ports', service)
        self.assertEqual(service['expose'], ['3001'])
        self.assertNotIn('chat', checks.HOST_PUBLISHED_SERVICES,
                         'the widening lands with the tuple assertion in tests/test_ai_component.py, '
                         'in one commit (CONTRACT.md section 3)')
        body = MANIFEST.read_text(encoding='utf-8')
        self.assertIn(INTENDED_PUBLICATION, body)
        active = [line for line in body.splitlines()
                  if re.match(r'^\s*ports:', line) and not line.lstrip().startswith('#')]
        self.assertEqual(active, [], 'a live ports: line without the widened list is a red gate')

    def test_the_shipped_documents_cite_code_and_tests_not_a_private_tracker(self):
        """No `card #N` / `PR #N` in the three prose documents a reader of this tree can act on."""
        for name in ('CONTRACT.md', 'conformance.md', 'versions.json'):
            with self.subTest(document=name):
                body = (COMPONENT / name).read_text(encoding='utf-8')
                self.assertEqual(FORGE_SHORTHAND.findall(body), [],
                                 f'{name} cites a tracker number instead of the code or test that '
                                 f'proves the claim')

    def test_the_healthcheck_is_the_upstream_endpoint_and_can_actually_go_red(self):
        """Upstream's own script parses the code in bash; an exec-form copy would always exit 0."""
        health = model()['services']['chat']['healthcheck']
        self.assertEqual(health['test'], ['CMD', 'curl', '-fsS', 'http://127.0.0.1:3001/api/ping'])
        self.assertTrue(any(item.startswith('-f') for item in health['test']),
                        'without -f the probe never fails and `compose ps` lies about a dead server')
        # One minute is upstream's own start_period; doubled because this repository has never
        # watched the thing boot, and a false `healthy` is a lie told to `compose ps`.
        self.assertEqual(health['start_period'], '120s')

    def test_every_upstream_claim_carries_a_source_and_a_date(self):
        """A version claim without a URL and a read date is the thing docs truth exists to remove.

        The URLs live in `versions.json` (that is where a reader goes to re-resolve a digest) and the
        dated reading lives in the contract, so both files are checked against the same day rather than
        each being trusted to hold both halves.
        """
        contract = ' '.join((COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8').split())
        pin = (COMPONENT / 'versions.json').read_text(encoding='utf-8')
        self.assertIn('2026-09-09', contract)
        self.assertIn('2026-09-09', pin)
        self.assertIn('github.com/Mintplex-Labs/anything-llm', pin)
        self.assertIn('hub.docker.com/v2/repositories/mintplexlabs/anythingllm', pin)
        self.assertIn('35c58d89907e675a8c4fb10544c19be0f050f611', contract)
        self.assertIn('UNVERIFIED', contract)
        self.assertIn('blocked-on-MCP component',
                      (COMPONENT / 'conformance.md').read_text(encoding='utf-8'),
                      'the omitted dependency is named as omitted, per docs/CONTRACTS.md §6')

    def test_the_contract_says_what_the_seam_is_worth_before_r_c04_lands(self):
        """The honest status of design clause 2: the capability is real, the tool is not."""
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        self.assertIn('StreamableHTTPClientTransport', contract)
        self.assertIn('anythingllm_mcp_servers.json', contract)
        self.assertIn('unbuilt', contract.lower())


class PinDocumentTests(unittest.TestCase):
    def setUp(self):
        self.document = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))

    def test_the_pin_records_a_digest_it_read_and_the_size_that_came_with_it(self):
        image = self.document['image']
        self.assertEqual(image['release'], 'v1.16.1')
        self.assertRegex(image['image_digest'], r'^sha256:[0-9a-f]{64}$')
        self.assertRegex(image['linux_amd64_digest'], r'^sha256:[0-9a-f]{64}$')
        self.assertEqual(image['compressed_size_bytes']['amd64'], 1101725314)
        self.assertIsNone(image['compressed_size_bytes']['uncompressed_bytes'],
                          'the registry reports the compressed total; anything else here would be '
                          'an invention')
        self.assertEqual(image['digest_provenance']['read_on'], '2026-09-09')
        self.assertEqual(image['licence']['spdx'], 'MIT')

    def test_the_file_states_its_own_unknowns_instead_of_implying_a_run(self):
        self.assertIsNone(self.document['verified_on'])
        self.assertEqual(self.document['status'], 'selected')
        self.assertTrue(self.document['unverified'], 'an empty unknowns list is the claim that there '
                                                     'are none')
        validation = self.document['validation']
        self.assertTrue(validation['image_digests_resolved'])
        for key in ('image_pulled', 'container_started', 'component_in_an_example'):
            self.assertFalse(validation[key], f'{key} would be a claim about a run')
        for key in ('runtime_conformance', 'backup_restore', 'upgrade_rehearsal'):
            self.assertTrue(str(validation[key]).startswith('not-run'),
                            f'{key} reads {validation[key]!r}: a verdict word, not a claim dressed as one')
        self.assertIn('MCP component', validation['approval_separation'])

    def test_the_ram_figure_is_named_against_q33_and_says_whose_number_it_is(self):
        requirements = self.document['system_requirements']
        self.assertEqual(requirements['recommended_minimum']['ram'], '2 GB')
        self.assertIn('AVX2', requirements['hard_requirement'])
        self.assertIn('standard', requirements['against_q33'])
        self.assertIn('16 GB', requirements['against_q33'])

    def test_the_provisional_half_of_q16_and_the_hermes_question_are_still_open_on_the_page(self):
        """Candidate metadata must leave client selection and runtime compatibility open."""
        self.assertIn('provisional', self.document['provisional'])
        hermes = self.document['hermes_identity']
        self.assertEqual(hermes['state'].split(' ')[0], 'OPEN')
        self.assertIn('Select', hermes['ask'])
        self.assertIn('upstream', hermes['ask'])
        self.assertIn('candidate', hermes['what_was_read'],
                      'an upstream project named here is a candidate for the name chat integration uses, not an '
                      'identification of it')
        self.assertIn('Compatibility with the assistant client selected by the operator.',
                      self.document['unverified'])


class AbsentByDefaultTests(unittest.TestCase):
    def test_no_example_composes_the_component(self):
        """`minimal`/`standard`/`full` must not need a 1.1 GB image or a chat credential to boot."""
        for name in checks.EXAMPLE_MANIFESTS:
            body = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn('control/chat', body,
                             f'{name} would make a provisional component a boot need')

    def test_the_full_example_service_set_has_no_chat_service(self):
        services, errors = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        self.assertEqual(errors, [])
        self.assertNotIn('chat', services)

    def test_the_full_example_template_carries_no_active_chat_variable(self):
        body = (ROOT / 'examples/full/.env.example').read_text(encoding='utf-8')
        active = [line for line in body.splitlines() if re.match(r'^LO_CHAT_[A-Z_]+=', line)]
        self.assertEqual(active, [], 'a live LO_CHAT_* line makes the example require a chat install')
        self.assertIn('LO_CHAT_IMAGE', body, 'the opt-in is not documented if no line names it')

    def test_operation_without_telegram_ships_zero_telegram_configuration(self):
        """integration validation's last chat clause and chat integration's complaint, read off the shipped tree (conformance row 5).

        What is pinned is the absence of a *configuration path*, not the absence of the word: the
        documents name the pinned build's Telegram connector precisely to refuse it (CONTRACT.md
        section 6), and a test that banned the noun would have to be deleted the first time a
        sentence explained the refusal. A token, a bot key or a `TELEGRAM`-shaped variable in the
        manifest or in an example's opt-in lines is the thing that must not appear.
        """
        rendered = json.dumps(environment(), sort_keys=True).upper()
        for token in ('TELEGRAM', 'BOT_TOKEN', 'BOTA', 'TELEGRAM_CONFIG'):
            with self.subTest(token=token):
                self.assertNotIn(token, rendered)
        self.assertNotIn('LO_TELEGRAM_CONFIG', MANIFEST.read_text(encoding='utf-8'),
                         'the product notification rail is notifications/delivery channels\'s; a chat manifest that '
                         'wires it has started a second approval path')
        template = (ROOT / 'examples/full/.env.example').read_text(encoding='utf-8')
        chat_lines = [line for line in template.splitlines() if 'LO_CHAT' in line]
        self.assertTrue(chat_lines, 'the opt-in must be findable')
        for line in chat_lines:
            with self.subTest(line=line[:48]):
                self.assertNotRegex(line, r'(?i)telegram')


if __name__ == '__main__':
    unittest.main()
