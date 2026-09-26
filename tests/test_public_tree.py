"""Public source checks use synthetic identities; real inventories stay outside source."""
from pathlib import Path
import tempfile
import unittest

from scripts.check_public_tree import check, policy_tokens


class PublicTreeTests(unittest.TestCase):
    def test_identifiers_in_hidden_files_names_and_utf16_are_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                '.settings': b'PRIVATE-IDENTITY',
                'private-identity.txt': b'ordinary text',
                'encoded.txt': 'private-identity'.encode('utf-16-le'),
                'clean.txt': b'example.invalid',
            }
            for name, body in fixtures.items():
                (root / name).write_bytes(body)
            errors = check(root, list(fixtures), ('private-identity',))
            self.assertEqual(len(errors), 3)
            self.assertTrue(all('external identifier policy match' in error for error in errors))

    def test_links_and_private_artifacts_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('[missing](missing.md)\n[web](https://example.invalid)\n', encoding='utf-8')
            (root / '.env').write_text('DEMO=1', encoding='utf-8')
            errors = check(root, ['README.md', '.env'])
            self.assertEqual(len(errors), 2)

    def test_policy_cannot_be_kept_in_the_source_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / 'policy.json'
            policy.write_text('{"forbidden": ["private-identity"]}', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'outside'):
                policy_tokens(policy, root)

    def test_linked_sources_do_not_escape_the_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            try:
                (root / 'linked.txt').symlink_to(root / 'missing.txt')
            except OSError:
                self.skipTest('symlinks unavailable')
            self.assertEqual(len(check(root, ['linked.txt'])), 1)
