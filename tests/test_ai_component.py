"""Structural tests for the `ai` component: the manifest, the absence, and who may import what.

These are the tests that make the two sentences in `docs/COMPONENTS.md` checkable rather than
aspirational — the `If disabled` column ("Rules and operator workflows work without generation") and
the §4 claim that selecting AI never becomes a hidden prerequisite. Both are properties of the import
graph and of the shipped files, so both are tested as such.
"""
import ast
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from local_observe.ai import capability, policy
from local_observe.platform import overview_worker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks

COMPONENT = ROOT / 'components' / 'control' / 'ai'
PACKAGE = ROOT / 'local_observe' / 'ai'
# Paths allowed to import the ai package outside it, each with the one-sentence reason it earns the
# exception. Empty on purpose: the `If disabled` column has no exception yet, and an entry without a
# reason is treated as a failure by the test below, the same way `CREDENTIAL_ENV_EXCEPTIONS` in
# scripts/check_foundation.py refuses a blank waiver.
ALLOWED_IMPORTERS: dict[str, str] = {}


def product_modules():
    """Every product module outside `local_observe/ai/`, as (path, relative posix name)."""
    for path in sorted((ROOT / 'local_observe').rglob('*.py')):
        relative = path.relative_to(ROOT).as_posix()
        if not relative.startswith('local_observe/ai/'):
            yield path, relative


def imports_ai(path: Path) -> bool:
    """Whether *path* names `local_observe.ai` in an import statement, read from its syntax tree."""
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or '').startswith('local_observe.ai'):
            return True
        if isinstance(node, ast.Import):
            if any(alias.name.startswith('local_observe.ai') for alias in node.names):
                return True
    return False


class ShippedArtefactsTests(unittest.TestCase):
    def test_the_five_artefacts_and_the_manifest_are_all_present(self):
        """quality bar counts five artefacts per component; the row cannot be called built without them."""
        for name in ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md', 'versions.json',
                     'compose.yaml'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_manifest_passes_the_model_rules_the_gate_uses(self):
        """No example includes this file, so `check_example` never reaches it — this test does."""
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertEqual(checks.check_model(model, COMPONENT), [])
        self.assertEqual(checks.check_credential_files(model), [])

    def test_the_manifest_publishes_nothing_and_the_gate_list_is_untouched(self):
        """Consumers are containers on the project network, so `ai` is not a host-published service."""
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        self.assertNotIn('ports', model['services']['ai'])
        self.assertNotIn('ai', checks.HOST_PUBLISHED_SERVICES)
        # The list is pinned so no row widens it silently. `healthchecks` is in it from job observe standard (component
        # `job-observe`, decision job observation); `ai` adds no name. `mcp` joined it in MCP component with the argument in
        # the comment above the tuple in scripts/check_foundation.py — a loopback publication for a
        # caller that is not a container on this network — and `homepage` is there from operator portal.
        self.assertEqual(checks.HOST_PUBLISHED_SERVICES,
                         ('signoz', 'lo-front-door', 'platform', 'inventory', 'dagu',
                          'healthchecks', 'homepage', 'mcp'))

    def test_the_manifest_carries_only_a_credential_path_and_the_gate_cannot_see_the_name(self):
        """Both halves of the naming decision in AI integration task 4, pinned instead of relied on.

        The credential rule in `check_foundation.py` matches `LO_` names ending in `_TOKEN`,
        `_PASSWORD` or `_SECRET`. `LO_AI_API_KEY_FILE` matches none of them, so the gate cannot police
        this credential under any spelling of "API key" — which is why the manifest carries a mount
        path and why that gap is asserted here rather than discovered by the next reader.
        """
        body = (COMPONENT / 'compose.yaml').read_text(encoding='utf-8')
        self.assertIn('LO_AI_API_KEY_FILE', body)
        self.assertNotIn('LO_AI_API_KEY:', body)
        self.assertIn('run/secrets/ai-api-key', body)
        model = checks.read_yaml(COMPONENT / 'compose.yaml')
        environment = checks.compose_environment(model['services']['ai'])
        self.assertNotIn('LO_AI_API_KEY', environment)
        # The blind spot itself: a bare API-key value in an environment block passes the credential
        # rule, because the rule's three suffixes do not include it. If the pattern is ever widened,
        # this assertion fails and the change has to be argued on its own card, not in this one.
        with tempfile.TemporaryDirectory():
            leaky = {'services': {'ai': {'image': '${LO_AI_IMAGE:?pin}',
                                        'environment': {'LO_AI_API_KEY': 'a-secret-value'}}}}
            self.assertEqual(checks.check_credential_files(leaky), [],
                             'the credential rule now sees _API_KEY: update CONTRACT.md and AI integration task 4')

    def test_the_serve_command_does_not_enable_tools_or_the_web_ui(self):
        """`--tools` turns a text endpoint into a file/exec agent; the manifest must never do that."""
        command = ' '.join(checks.read_yaml(COMPONENT / 'compose.yaml')['services']['ai']['command'])
        self.assertNotIn('--tools', command)
        self.assertIn('--no-webui', command)
        self.assertIn('--no-slots', command)
        self.assertIn('--api-key-file', command)

    def test_the_weights_arrive_as_an_operator_supplied_read_only_bind(self):
        volumes = checks.read_yaml(COMPONENT / 'compose.yaml')['services']['ai']['volumes']
        binds = [item for item in volumes if isinstance(item, dict)]
        self.assertEqual(len(binds), 1)
        self.assertTrue(binds[0]['source'].startswith('${LO_AI_MODEL_DIR:'))
        self.assertEqual(binds[0]['target'], '/models')
        self.assertTrue(binds[0]['read_only'])
        self.assertIs(binds[0]['bind']['create_host_path'], False)
        self.assertEqual(checks.read_yaml(COMPONENT / 'compose.yaml').get('volumes') or {}, {},
                         'the serve holds no state, so it declares no volume')

    def test_versions_json_states_what_is_unverified_instead_of_implying_it_is_known(self):
        document = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.assertIsNone(document['serve']['image_digest'])
        self.assertEqual(document['serve']['build_tag_for_this_release'], 'UNVERIFIED')
        self.assertTrue(document['serve']['unverified'])
        self.assertEqual(document['validation']['runtime_conformance'], 'not-run')
        self.assertFalse(document['validation']['container_started'])
        self.assertFalse(document['validation']['component_in_an_example'])
        self.assertEqual(document['capability_manifest']['fields_measured'], 0)

    def test_the_shipped_examples_and_policy_files_are_the_documents_they_claim_to_be(self):
        document = capability.load(COMPONENT / 'capability.example.json')
        self.assertEqual(len(capability.unknown(document)), 7)
        self.assertFalse(document['tools'])
        decided = policy.load(COMPONENT / 'policy.example.json')
        for name in policy.DATA_CLASSES:
            self.assertFalse(decided['classes'][name]['remote'])
        self.assertEqual(decided['classes']['restricted']['generate'], False)

    def test_every_upstream_claim_in_the_contract_carries_a_source_and_a_date(self):
        """A version claim without a URL and a read date is the thing docs truth exists to remove."""
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        self.assertIn('2026-09-08', contract)
        self.assertIn('github.com/ggml-org/llama.cpp/blob/v0.4.0', contract)
        self.assertIn('UNVERIFIED', contract)
        self.assertIn('not run', (COMPONENT / 'conformance.md').read_text(encoding='utf-8'))


class AbsentByDefaultTests(unittest.TestCase):
    def test_no_example_composes_the_component(self):
        """`minimal`/`standard`/`full` must not need an image, weights or an AI key to boot."""
        for name in checks.EXAMPLE_MANIFESTS:
            body = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn('control/ai', body, f'{name} would make an optional component a boot need')

    def test_the_full_example_template_carries_no_active_ai_variable(self):
        body = (ROOT / 'examples/full/.env.example').read_text(encoding='utf-8')
        active = [line for line in body.splitlines()
                  if re.match(r'^LO_AI_[A-Z_]+=', line)]
        self.assertEqual(active, [], 'a live LO_AI_* line makes the example require an AI install')
        self.assertIn('LO_AI_IMAGE', body, 'the opt-in is not documented if no line names it')

    def test_the_full_example_service_set_has_no_ai_service(self):
        services, errors = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        self.assertEqual(errors, [])
        self.assertNotIn('ai', services)

    def test_the_capability_field_list_does_not_drift_from_the_package(self):
        """Two copies of a list that must move together, pinned the way the event `kind` list is."""
        self.assertEqual(tuple(overview_worker.MODEL_CAPABILITY_FIELDS), capability.FIELDS)


class ImportGraphTests(unittest.TestCase):
    def test_nothing_outside_the_package_imports_it(self):
        """`rca` and `chat` import lazily when they arrive (investigation component, chat integration); today, nothing does."""
        for path, relative in product_modules():
            with self.subTest(module=relative):
                if imports_ai(path):
                    self.assertIn(relative, ALLOWED_IMPORTERS,
                                  'a product module outside local_observe/ai/ now depends on '
                                  'generation; that is the hidden prerequisite the component row '
                                  'denies, so either remove it or record why with a reason')
                    self.assertTrue(ALLOWED_IMPORTERS[relative].strip(),
                                    'an importer exception must state its reason in one sentence')

    def test_the_package_cannot_reach_the_store_so_it_cannot_re_query_expired_evidence(self):
        """The refusal in query adapter is structural: no query builder, no state store, no second transport."""
        forbidden = ('local_observe.platform', 'sigma_runner', 'import sqlite3', 'from local_observe'
                     '/platform', 'datasette')
        for path in sorted(PACKAGE.glob('*.py')):
            body = path.read_text(encoding='utf-8')
            for token in forbidden:
                with self.subTest(module=path.name, token=token):
                    self.assertNotIn(token, body)
        # The one shared transport, and no new HTTP client of its own.
        self.assertIn('local_observe.http', (PACKAGE / 'client.py').read_text(encoding='utf-8'))

    def test_the_whole_product_import_graph_works_with_the_ai_package_removed(self):
        """The experiment behind §4's "no hidden prerequisite", run as a check and not as a sentence.

        A meta-path blocker makes `local_observe.ai` raise ImportError for anything that asks for it,
        then every other product module is imported in a fresh interpreter. A module that turns out to
        need the optional package is reported by name; missing *third-party* extras (uvicorn, mcp) are
        the tiers' business and are ignored here, exactly as `docs/testing-standards.md` separates them.
        """
        script = """
import importlib, json, pathlib, sys
ROOT = pathlib.Path(sys.argv[1])
class Block:
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'local_observe.ai' or fullname.startswith('local_observe.ai.'):
            raise ImportError('blocked: ' + fullname)
        return None
sys.meta_path.insert(0, Block())
blocked = []
for file in sorted((ROOT / 'local_observe').rglob('*.py')):
    if file.name in ('__init__.py', '__main__.py'):
        continue          # packages are reached through their modules, and __main__ files parse argv
    name = file.relative_to(ROOT).with_suffix('').as_posix().replace('/', '.')
    if name.startswith('local_observe.ai'):
        continue
    try:
        importlib.import_module(name)
    except ImportError as error:
        if 'blocked:' in str(error):
            blocked.append([name, str(error)])
print(json.dumps(blocked))
"""
        result = subprocess.run([sys.executable, '-B', '-c', script, str(ROOT)],
                                capture_output=True, text=True, cwd=str(ROOT), timeout=300,
                                env=dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1'))
        self.assertEqual(result.returncode, 0, result.stderr[-800:])
        self.assertEqual(json.loads(result.stdout.strip().splitlines()[-1]), [],
                         'something imports local_observe.ai and so cannot boot without it')


if __name__ == '__main__':
    unittest.main()
