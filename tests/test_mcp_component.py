"""Structural tests for the `mcp` component: the packaging, the split, and the numbers the row claims.

MCP component's scope is the *image*, not the surface: the registry, the identity map and the refusal matrix
arrived with mcp tool surface and the action execution boundary and are tested in `tests/test_platform_tools.py` and
`tests/test_mcp_surface.py`. What is pinned here is the part that did not exist before this directory —
the claims that make it a deployable component rather than a module:

* the five quality bar artefacts plus the four files that make an image (requirements, lock, Dockerfile,
  compose), with the manifest passing the product's own gate;
* the split the separate image rests on: the platform image still refuses the extra, exactly one product
  module imports the SDK, and no shipped example needs an MCP image to boot;
* the counts. The row's role says "gated requests" and CONTRACT.md says *exactly one* propose->execute
  pair, so the pair is counted off the registry rather than adjectived, and `versions.json`'s numbers are
  compared against the live registry instead of restated as prose.

Base tier: imports `local_observe.platform.tools` (SDK-free by design) and never `mcp`.
"""
import ast
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks  # noqa: E402  (the script tree is not a package)

from local_observe.platform import tools  # noqa: E402

COMPONENT = ROOT / 'components' / 'control' / 'mcp'
PLATFORM = ROOT / 'components' / 'control' / 'platform'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
REQUIREMENT = re.compile(r'^([A-Za-z0-9_.-]+)==([^\s\\]+)')
HASH_LINE = re.compile(r'^\s+--hash=sha256:([0-9a-f]{64})$')

DIRECT_REQUIREMENTS = ['jsonschema', 'mcp', 'pyyaml', 'uvicorn']
SHARED_WITH_PLATFORM = ['attrs', 'click', 'h11', 'jsonschema', 'jsonschema-specifications', 'pyyaml',
                        'referencing', 'rpds-py', 'typing-extensions', 'uvicorn']
V0_1_READS = ['inventory', 'platform_overview', 'platform_status', 'records']
MAP_SURFACE = ['component_boundary', 'evidence_window', 'execute_action', 'inventory', 'platform_overview',
               'platform_status', 'propose_action', 'records']


def lock_requirements(path: Path) -> dict:
    """Return ``{package: (version, [sha256, …])}`` read from a hash-locked requirements file."""
    result: dict = {}
    current = None
    for line in path.read_text(encoding='utf-8').splitlines():
        named = REQUIREMENT.match(line)
        if named:
            current = named.group(1).lower().replace('_', '-')
            result[current] = (named.group(2), [])
            continue
        digest = HASH_LINE.match(line)
        if digest is not None and current is not None:
            version, hashes = result[current]
            result[current] = (version, hashes + [digest.group(1)])
    return result


def compose() -> dict:
    """The component manifest, through the same loader the gate uses."""
    return checks.read_yaml(COMPONENT / 'compose.yaml')


def service() -> dict:
    """The one service the manifest declares."""
    return compose()['services']['mcp']


def pyproject_extra_pin() -> str:
    """The version ``[project.optional-dependencies] mcp`` pins, read from pyproject.toml's text."""
    body = (ROOT / 'pyproject.toml').read_text(encoding='utf-8')
    match = re.search(r'^mcp\s*=\s*\[\s*"mcp==([^"]+)"', body, re.M)
    assert match, 'pyproject.toml no longer pins an `mcp` extra in the shape this test reads'
    return match.group(1)


def versions() -> dict:
    return json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))


def included_manifests(example: Path) -> list:
    """Every component Compose file *example* pulls in, in include order (the walk the gate does)."""
    files: list = []
    for entry in checks.read_yaml(example).get('include') or []:
        files.extend(checks.include_entry(entry, example.parent)[0])
    return files


class ShippedArtefactsTests(unittest.TestCase):
    """quality bar's five artefacts, plus the files that make the row buildable at all."""

    def test_the_five_artefacts_and_the_build_inputs_are_all_present(self):
        for name in ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md', 'versions.json',
                     'compose.yaml', 'Dockerfile', 'requirements.in', 'requirements.lock'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_manifest_passes_the_model_rules_the_gate_uses(self):
        """No shipped example includes this file, so check_example never reaches it — this test does."""
        model = compose()
        self.assertEqual(checks.check_model(model, COMPONENT), [])
        self.assertEqual(checks.check_credential_files(model), [])
        self.assertEqual(checks.check_delivery(model), [],
                         'this service must not become a second platform process by accident')

    def test_the_image_is_required_the_pull_is_refused_and_nothing_is_guessed(self):
        served = service()
        self.assertEqual(served['image'], '${LO_MCP_IMAGE:?pin the MCP tool-surface image}')
        self.assertEqual(served['pull_policy'], 'never')
        self.assertTrue(served['read_only'])
        self.assertEqual(served['user'], '65532:65532')
        self.assertEqual(served['cap_drop'], ['ALL'])
        self.assertEqual(served['security_opt'], ['no-new-privileges:true'])
        for key in ('mem_limit', 'cpus', 'pids_limit'):
            self.assertIn(key, served, f'the resource bound {key} is what makes this a bounded process')

    def test_the_only_host_port_is_the_loopback_line_and_the_tuple_carries_the_argument(self):
        """The widening, from this side: an argued name in the tuple and one loopback line in the file."""
        self.assertEqual(service()['ports'], ['127.0.0.1:${LO_MCP_PORT:-18100}:8003'])
        self.assertIn('mcp', checks.HOST_PUBLISHED_SERVICES)
        # The argument is not decoration. `HOST_PUBLISHED_SERVICES` is preceded by the comment that makes
        # the case for this name; a widening that arrives without it is the defect the tuple comment
        # exists to catch, so the comment is asserted rather than trusted.
        source = (ROOT / 'scripts' / 'check_foundation.py').read_text(encoding='utf-8').splitlines()
        declared = next(index for index, line in enumerate(source)
                        if line.startswith('HOST_PUBLISHED_SERVICES = '))
        preamble = ' '.join(source[max(0, declared - 22):declared])
        self.assertIn('mcp', preamble)
        self.assertIn('MCP component', preamble)
        self.assertIn('127.0.0.1', preamble)

    def test_the_default_host_port_is_not_one_a_shipped_example_hands_out(self):
        """18100 collides with nothing: demo, full and the platform stage are read, includes included."""
        taken = set()
        for name in checks.EXAMPLE_MANIFESTS:
            example = ROOT / name
            for path in [example] + [item.resolve() for item in included_manifests(example)]:
                taken.update(re.findall(r'(?m)^LO_[A-Z_]*PORT=(\d+)$', path.read_text(encoding='utf-8')))
                taken.update(re.findall(r'\$\{LO_[A-Z_]*PORT:-(\d+)\}', path.read_text(encoding='utf-8')))
                taken.update(re.findall(r'(?m)^\s+- \"?127\.0\.0\.1:(\d{4,5})', path.read_text(encoding='utf-8')))
        self.assertNotIn('18100', taken, f'the default published port collides with {sorted(taken)}')
        self.assertNotIn('18098', taken, 'the restore-scratch port these examples leave free has moved')

    def test_the_manifest_declares_no_volume_and_no_secrets_block(self):
        """Two absences, each a decision: stateless by design, and a required secret is not optional.

        A Compose `secrets:` entry cannot be declared conditionally, so a required one would stop the
        install that mounts no identity map at all — the same reasoning the platform manifest records for
        LO_NOTIFY_CHANNELS. Every credential here is a path inside the one read-only policy bind.
        """
        model = compose()
        self.assertEqual(model.get('volumes') or {}, {})
        self.assertNotIn('secrets', model)
        self.assertNotIn('secrets', service())
        binds = [item for item in service()['volumes'] if isinstance(item, dict)]
        self.assertEqual([item['target'] for item in binds], ['/config', '/inventory'])
        for bind in binds:
            with self.subTest(target=bind['target']):
                self.assertTrue(bind['read_only'])
                self.assertIs(bind['bind']['create_host_path'], False)
        # The policy bind is the PLATFORM's variable, not a new one: one staged map, one file, two
        # readers. A second variable naming a second copy is two files that drift on a rotation.
        self.assertEqual([item['source'] for item in binds],
                         ['${LO_PLATFORM_POLICY_DIR:?action policy directory (holds the MCP identity map)}',
                          '${LO_INVENTORY_SNAPSHOT_DIR:?immutable inventory snapshot directory}'])

    def test_the_healthcheck_probes_without_sending_a_credential(self):
        """The probe proves the gate answers; it must not need a secret to find that out."""
        probe = ' '.join(str(part) for part in service()['healthcheck']['test'])
        self.assertIn('401', probe, 'the probe is a negative test: 401 is the answer that means alive')
        self.assertNotIn('Authorization', probe)
        self.assertNotIn('LO_MCP_IDENTITIES', probe)
        self.assertIn('127.0.0.1:8003', probe)
        self.assertEqual(service()['logging']['driver'], 'json-file')
        self.assertEqual(service()['logging']['options'], {'max-size': '5m', 'max-file': '2'})

    def test_versions_json_states_the_validation_honestly_and_the_split_it_rests_on(self):
        document = versions()
        self.assertIn(document['status'], ('selected', 'experimental', 'validated'),
                      'the validation vocabulary in docs/COMPONENTS.md 2 is the only one a pin file speaks')
        self.assertEqual(document['status'], 'experimental')
        self.assertIsNone(document['verified_on'])
        self.assertIsNone(document['image']['identity'],
                          'an image id is written after a container has served a real request, not before')
        self.assertFalse(document['validation']['container_started'])
        self.assertFalse(document['validation']['image_built'])
        self.assertFalse(document['validation']['lock_installed'])
        self.assertEqual(document['validation']['runtime_conformance'], 'not-run')
        self.assertTrue(document['unverified'], 'a versions.json with an empty unverified list is a claim')
        self.assertEqual(document['sdk']['version'], pyproject_extra_pin())
        platform_base = json.loads((PLATFORM / 'versions.json').read_text(encoding='utf-8'))['python_base']
        self.assertEqual(document['python_base'], platform_base,
                         'two first-party images on two interpreter pins is a debugging session')

    def test_conformance_marks_every_runtime_row_not_run_rather_than_leaving_it_blank(self):
        body = (COMPONENT / 'conformance.md').read_text(encoding='utf-8')
        self.assertGreaterEqual(body.count('**not-run**'), 11,
                                'a row with no state reads as a row that ran')
        self.assertNotIn('| **pass** |', body,
                         'nothing has been run from this directory; a pass row would be fabricated')
        self.assertIn('components/control/platform/conformance.md', body,
                      'the chat integration recipe this packaging makes runnable is named, not replaced')


class LockTests(unittest.TestCase):
    """The hash lock, as a document that has to agree with the rest of the tree."""

    def test_every_requirement_is_hash_locked_and_no_hash_dangles(self):
        locked = lock_requirements(COMPONENT / 'requirements.lock')
        self.assertGreaterEqual(len(locked), 20,
                                'the SDK closure is twenty packages deep; a shorter lock is a partial one')
        for package, (_version, hashes) in sorted(locked.items()):
            with self.subTest(package=package):
                self.assertTrue(hashes, 'a requirement with no --hash line fails --require-hashes')
                for digest in hashes:
                    self.assertTrue(HEX64.match(digest), f'{package}: {digest} is not a sha256')
        body = (COMPONENT / 'requirements.lock').read_text(encoding='utf-8')
        self.assertEqual(re.findall(r'(?m)^--hash=', body), [],
                         'a --hash line must be a continuation of a requirement line, or pip reads it as '
                         'a hash of nothing')

    def test_the_direct_requirements_are_the_four_named_at_the_versions_the_product_pins(self):
        locked = lock_requirements(COMPONENT / 'requirements.lock')
        direct = lock_requirements(COMPONENT / 'requirements.in')
        self.assertEqual(sorted(direct), DIRECT_REQUIREMENTS)
        for package, (version, _hashes) in direct.items():
            with self.subTest(package=package):
                self.assertIn(package, locked, 'a direct requirement missing from the lock')
                self.assertEqual(locked[package][0], version, 'the lock drifted from requirements.in')
        self.assertEqual(locked['mcp'][0], pyproject_extra_pin(),
                         "the image pin and pyproject.toml's `mcp` extra must agree: an image built "
                         'against another SDK is a different protocol surface than CONTRACT.md describes')

    def test_the_lock_carries_no_package_that_only_an_extra_or_another_platform_wants(self):
        locked = lock_requirements(COMPONENT / 'requirements.lock')
        for absent in ('pywin32', 'typer', 'rich', 'websockets', 'sniffio', 'trio', 'pytest'):
            with self.subTest(package=absent):
                self.assertNotIn(absent, locked,
                                 'a Windows-only requirement or an SDK extra has no business in a '
                                 'linux/amd64 image lock, and pywin32 is exactly what the header says uv '
                                 'was needed to keep out')

    def test_the_lock_header_keeps_its_own_count(self):
        """The header states how many hashes were recomputed from downloaded bytes; a stale number is a false claim."""
        body = (COMPONENT / 'requirements.lock').read_text(encoding='utf-8')
        stated = re.search(r'all (\d+) hashes below', body)
        self.assertIsNotNone(stated, 'the header must name what was verified, and how many')
        self.assertEqual(int(stated.group(1)), body.count('--hash='))

    def test_the_packages_shared_with_the_platform_image_agree_on_version_and_digest(self):
        locked = lock_requirements(COMPONENT / 'requirements.lock')
        platform = lock_requirements(PLATFORM / 'requirements.lock')
        self.assertEqual(sorted(set(locked) & set(platform)), SHARED_WITH_PLATFORM)
        self.assertNotIn('mcp', platform, 'the platform image keeps the extra uninstalled, which is the '
                                          'division this component exists to keep')
        for package in SHARED_WITH_PLATFORM:
            with self.subTest(package=package):
                self.assertEqual(locked[package][0], platform[package][0],
                                 'the two images disagree about a version both of them installs')
                self.assertTrue(set(platform[package][1]) <= set(locked[package][1]),
                                "the platform's digest is not among this lock's hashes for that package")


class DockerfileTests(unittest.TestCase):
    """The build recipe as text: the base, the lock, the entry point, and the extra that stays absent."""

    def setUp(self):
        self.body = (COMPONENT / 'Dockerfile').read_text(encoding='utf-8')
        self.platform = (PLATFORM / 'Dockerfile').read_text(encoding='utf-8')

    def test_both_images_start_from_the_same_pinned_interpreter(self):
        digest = re.search(r'ARG LO_PYTHON_IMAGE=python:3\.12-slim@sha256:([0-9a-f]{64})', self.body)
        self.assertIsNotNone(digest, 'the base image must be pinned by digest, not by tag')
        self.assertIn(f'ARG LO_PYTHON_IMAGE=python:3.12-slim@sha256:{digest.group(1)}', self.platform)
        self.assertEqual(versions()['python_base'], f'library/python@sha256:{digest.group(1)}')

    def test_the_install_is_hash_locked_and_the_served_entry_point_is_the_mcp_factory(self):
        self.assertIn('--require-hashes', self.body)
        self.assertIn('-r /tmp/component/requirements.lock', self.body)
        self.assertIn('COPY local_observe /app/local_observe', self.body)
        self.assertIn('USER 65532:65532', self.body)
        self.assertIn('EXPOSE 8003', self.body)
        self.assertIn('local_observe.platform.mcp:app_factory', self.body)
        self.assertIn('"--factory"', self.body)
        self.assertIn('COPY components/control/mcp /tmp/component', self.body)
        runs = re.findall(r'(?m)^RUN[^\n]*', self.body)
        self.assertEqual(len(runs), 1,
                         'exactly one RUN in this image, and it installs the lock')
        self.assertIn('pip install', runs[0])
        self.assertNotIn('/data', runs[0], 'this process owns no state, so the build creates no /data')
        self.assertNotIn('VOLUME ', self.body)

    def test_the_platform_image_still_states_that_the_extra_is_not_installed_there(self):
        self.assertIn('Optional extras (mcp, pySigma) are not installed', self.platform)
        self.assertNotIn('mcp', lock_requirements(PLATFORM / 'requirements.lock'),
                         'the platform lock gained the SDK: the optional tier, integration validation and the base tier all '
                         'rest on this image not carrying it')

    def test_the_build_and_lock_recipes_are_written_in_docs_build_md(self):
        build = (ROOT / 'docs' / 'BUILD.md').read_text(encoding='utf-8')
        self.assertIn('components/control/mcp/Dockerfile', build)
        self.assertIn('components/control/mcp/requirements.in', build)
        self.assertRegex(build.split('\n## Prerequisites')[0], r'(?i)\bthree\b',
                         'the page must stop saying two images are built')


class SurfaceCountTests(unittest.TestCase):
    """"Exactly one pair" and "four reads" as numbers off the registry, not adjectives in a table."""

    def setUp(self):
        self.registry = tools.agent_registry(reader=None, index_path=None)
        self.reader = sorted(tools.reader_registry().names())
        self.agent = sorted(self.registry.names())

    def names_for(self, capability: str) -> list:
        """Every tool the registry registers under *capability*."""
        return sorted(item['name'] for item in self.registry.descriptors()
                      if item['capability'] == capability)

    def test_the_shared_token_surface_is_exactly_the_four_v0_1_reads(self):
        self.assertEqual(self.reader, V0_1_READS)

    def test_the_map_surface_adds_two_reads_one_boundary_and_the_single_action_pair(self):
        self.assertEqual(self.agent, MAP_SURFACE)
        self.assertEqual(self.names_for('propose'), ['propose_action'])
        self.assertEqual(self.names_for('execute'), ['execute_action'])
        self.assertEqual(self.names_for('read'), sorted(set(MAP_SURFACE) - {'propose_action',
                                                                           'execute_action'}))

    def test_the_maximum_is_ten_and_the_two_optional_tools_are_the_mounted_capabilities(self):
        self.assertEqual(len(set(self.agent) | {'signal_series', 'topology_neighbourhood'}), 10)
        document = versions()['surface']
        self.assertEqual(document['tools_with_one_shared_token'], self.reader)
        self.assertEqual(document['tools_with_a_per_agent_map'], self.agent)
        self.assertEqual(document['maximum_tools'], 10)
        self.assertEqual(document['action_pairs'], 1)
        self.assertEqual(sorted(document['tools_added_only_when_mounted']),
                         ['signal_series', 'topology_neighbourhood'])

    def test_no_tool_announces_a_hint_the_registry_refuses(self):
        for item in self.registry.descriptors():
            with self.subTest(tool=item['name']):
                self.assertEqual(item['capability'] == 'read', item['annotations']['readOnlyHint'],
                                 'a read must announce itself read-only and a gated tool must not')
                self.assertEqual(item['name'] == 'execute_action',
                                 item['annotations']['destructiveHint'],
                                 'Execution can cause approved external changes through the runner')
                self.assertEqual(item['name'] == 'execute_action',
                                 item['annotations']['openWorldHint'])


class OptionalByConstructionTests(unittest.TestCase):
    """`If disabled` as a structure: no example needs this image, and no module needs the SDK."""

    def test_no_shipped_example_composes_the_component(self):
        for name in checks.EXAMPLE_MANIFESTS:
            with self.subTest(example=name):
                body = (ROOT / name).read_text(encoding='utf-8')
                self.assertNotIn('control/mcp', body, 'an include here makes an optional component a '
                                                      'boot need for every install')
                self.assertNotIn('LO_MCP_IMAGE', body)
        services, errors = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        self.assertEqual(errors, [])
        self.assertNotIn('mcp', services)

    def test_the_full_example_template_documents_the_opt_in_without_requiring_it(self):
        body = (ROOT / 'examples/full/.env.example').read_text(encoding='utf-8')
        active = [line for line in body.splitlines() if re.match(r'^LO_MCP_[A-Z_]+=', line)]
        self.assertEqual(active, [], 'a live LO_MCP_* line makes the example require an MCP install')
        for named in ('LO_MCP_IMAGE', 'LO_MCP_PORT', 'LO_MCP_IDENTITIES'):
            self.assertIn(named, body, f'the opt-in is not documented if no line names {named}')

    def test_only_the_transport_module_ever_imports_the_sdk(self):
        """The absent-extra degradation is structural: one guarded import, and everything else is stdlib."""
        importers = []
        for path in sorted((ROOT / 'local_observe').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or '']
                else:
                    continue
                if any(name == 'mcp' or name.startswith('mcp.') for name in names):
                    importers.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(sorted(set(importers)), ['local_observe/platform/mcp.py'],
                         'a second module importing the SDK at module scope makes the extra a core '
                         'dependency and breaks the base tier')
        transport = (ROOT / 'local_observe' / 'platform' / 'mcp.py').read_text(encoding='utf-8')
        self.assertIn('except ModuleNotFoundError', transport,
                      'the one importer must refuse loudly rather than half-serve with no tools')


if __name__ == '__main__':
    unittest.main()
