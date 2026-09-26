"""Tests for the per-`data_class` policy: what remote inference policy forbids must be unconfigurable in the file."""
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.ai import policy
from local_observe.ai.policy import PolicyError

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_REMOTE = {'generate': True, 'remote': True, 'redact': ['secret_keys', 'no_free_text'],
                 'label': 'generated remotely; check the evidence'}
LOCAL_ONLY = {'generate': True, 'remote': False, 'redact': ['secret_keys'], 'label': ''}
REFUSED = {'generate': False, 'remote': False, 'redact': [], 'label': ''}


def policy_document(**classes):
    """A policy with the shipped three classes, overridden per *classes*."""
    merged = {'public': LOCAL_ONLY, 'internal': LOCAL_ONLY, 'restricted': REFUSED}
    merged.update(classes)
    return {'schema_version': 1, 'classes': merged}


class PolicyDecisionTests(unittest.TestCase):
    def test_restricted_is_refused_and_says_what_still_works(self):
        document = policy.validate(policy_document())
        with self.assertRaises(PolicyError) as caught:
            policy.decide(document, 'restricted', out_of_lan=False)
        self.assertEqual(caught.exception.code, 'policy_refused')
        self.assertIn('restricted', str(caught.exception))
        self.assertIn('without it', str(caught.exception))

    def test_refusal_per_class_when_the_endpoint_is_outside_the_lan(self):
        document = policy.validate(policy_document(public=PUBLIC_REMOTE))
        self.assertTrue(policy.decide(document, 'public', out_of_lan=True)['allowed'])
        for name in ('internal', 'restricted'):
            with self.subTest(data_class=name):
                with self.assertRaises(PolicyError) as caught:
                    policy.decide(document, name, out_of_lan=True)
                self.assertEqual(caught.exception.code, 'policy_refused' if name == 'restricted'
                                 else 'remote_refused')

    def test_an_unclassified_or_mistyped_class_is_refused_not_assumed_low(self):
        document = policy.validate(policy_document())
        for value in ('secret', 'PUBLIC', '', None, 1, 'internal '):
            with self.subTest(value=repr(value)):
                with self.assertRaises(PolicyError) as caught:
                    policy.decide(document, value, out_of_lan=False)
                self.assertEqual(caught.exception.code, 'policy_refused')

    def test_the_decision_carries_the_label_and_the_steps_and_nothing_else(self):
        decision = policy.decide(policy.validate(policy_document(public=PUBLIC_REMOTE)), 'public',
                                 out_of_lan=True)
        self.assertEqual(decision, {'allowed': True, 'data_class': 'public', 'out_of_lan': True,
                                   'redact': ['secret_keys', 'no_free_text'],
                                   'label': 'generated remotely; check the evidence'})

    def test_a_local_class_needs_no_label(self):
        decision = policy.decide(policy.validate(policy_document()), 'internal', out_of_lan=False)
        self.assertIsNone(decision['label'])
        self.assertEqual(decision['redact'], ['secret_keys'])


class PolicyFileTests(unittest.TestCase):
    def test_the_shipped_example_keeps_everything_inside_the_lan(self):
        document = policy.load(ROOT / 'components/control/ai/policy.example.json')
        self.assertEqual(document['classes']['restricted']['generate'], False)
        for name in policy.DATA_CLASSES:
            with self.subTest(data_class=name):
                self.assertFalse(document['classes'][name]['remote'],
                                 'the example must not pre-decide remote inference policy opt-in')
        with self.assertRaises(PolicyError):
            policy.decide(document, 'public', out_of_lan=True)

    def test_every_class_must_be_decided(self):
        for classes in ({'public': LOCAL_ONLY, 'internal': LOCAL_ONLY},
                        {name: LOCAL_ONLY for name in policy.DATA_CLASSES} | {'confidential': LOCAL_ONLY}):
            with self.subTest(classes=sorted(classes)):
                with self.assertRaises(PolicyError) as caught:
                    policy.validate({'schema_version': 1, 'classes': classes})
                self.assertIn('every data_class', str(caught.exception))

    def test_a_remote_class_is_impossible_without_label_and_free_text_redaction(self):
        """remote inference policy's "with redaction, and clearly labelled": neither is an option an operator can drop."""
        without_label = {**PUBLIC_REMOTE, 'label': ''}
        without_any_redaction = {**PUBLIC_REMOTE, 'redact': []}
        keys_only = {**PUBLIC_REMOTE, 'redact': ['secret_keys']}
        for entry in (without_label, without_any_redaction, keys_only, {**PUBLIC_REMOTE, 'generate': False}):
            with self.subTest(redact=entry['redact'], remote=entry['remote'], generate=entry['generate']):
                with self.assertRaises(PolicyError) as caught:
                    policy.validate(policy_document(public=entry))
                self.assertIn('remote', str(caught.exception))

    def test_restricted_may_never_leave_the_lan(self):
        """The threshold in remote inference policy is code, not a checkbox: no policy file can lift it."""
        with self.assertRaises(PolicyError) as caught:
            policy.validate(policy_document(restricted={**PUBLIC_REMOTE}))
        self.assertIn('restricted data may never', str(caught.exception))

    def test_redaction_steps_are_a_closed_unique_set(self):
        for steps in (['teleport'], ['secret_keys', 'secret_keys'], 'secret_keys', [None]):
            with self.subTest(steps=repr(steps)):
                with self.assertRaises(PolicyError):
                    policy.validate(policy_document(internal={**LOCAL_ONLY, 'redact': steps}))

    def test_types_bounds_and_shape(self):
        for document in ('x', [], {'schema_version': 1}, {'schema_version': 1, 'classes': 'x'},
                         {'schema_version': 2, 'classes': {'public': LOCAL_ONLY, 'internal': LOCAL_ONLY,
                                                           'restricted': REFUSED}},
                         {'schema_version': 1, 'classes': {'public': LOCAL_ONLY, 'internal': LOCAL_ONLY,
                                                           'restricted': {**REFUSED, 'generate': 'no'}}},
                         {'schema_version': 1, 'classes': {'public': {**LOCAL_ONLY, 'extra': 1},
                                                           'internal': LOCAL_ONLY, 'restricted': REFUSED}},
                         {'schema_version': 1, 'classes': {'public': {**LOCAL_ONLY, 'label': 'a' * 81},
                                                           'internal': LOCAL_ONLY, 'restricted': REFUSED}},
                         {'schema_version': 1, 'classes': {'public': {**LOCAL_ONLY, 'label': 'a\nb'},
                                                           'internal': LOCAL_ONLY, 'restricted': REFUSED}}):
            with self.subTest(document=repr(document)[:40]):
                with self.assertRaises(PolicyError):
                    policy.validate(document)

    def test_a_file_is_bounded_must_be_json_and_may_not_be_guessed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'policy.json').write_text(json.dumps(policy_document()), encoding='utf-8')
            self.assertEqual(policy.load(root / 'policy.json')['classes']['public'], LOCAL_ONLY)
            (root / 'big.json').write_text(json.dumps(policy_document(public={**PUBLIC_REMOTE,
                                                                              'redact': ['secret_keys',
                                                                                           'no_free_text'] * 200})),
                                           encoding='utf-8')
            with self.assertRaises(PolicyError):
                policy.load(root / 'big.json')
            (root / 'broken.json').write_text('[', encoding='utf-8')
            with self.assertRaises(PolicyError):
                policy.load(root / 'broken.json')
            with self.assertRaises(OSError):
                policy.load(root / 'absent.json')


class RedactionTests(unittest.TestCase):
    BUNDLE = [{'source': 'sigma-example', 'query_type': 'sigma-count',
               'parameters': {'rule_id': 'disk-full', 'artifact_sha256': 'a' * 64,
                              'password': 'hunter2',
                              'log_line': 'booted at ' + ('x' * 300), 'note': 'one line'},
               'window': {'start': '2026-09-08T10:00:00+00:00', 'end': '2026-09-08T10:05:00+00:00'},
               'schema_version': 1, 'expires_at': '2026-09-09T10:00:00+00:00'}]

    def test_secret_keys_are_removed_at_any_depth_using_the_log_formatter_s_name_set(self):
        scrubbed, counts = policy.redact(self.BUNDLE, ['secret_keys'])
        text = json.dumps(scrubbed)
        self.assertNotIn('hunter2', text)
        self.assertEqual(scrubbed[0]['parameters']['password'], policy.REDACTED_PLACEHOLDER)
        self.assertEqual(counts, {'secret_keys': 1})
        self.assertEqual(scrubbed[0]['parameters']['note'], 'one line', 'not a credential, not touched')

    def test_no_free_text_keeps_identifiers_and_drops_prose(self):
        scrubbed, counts = policy.redact(self.BUNDLE, ['no_free_text'])
        parameters = scrubbed[0]['parameters']
        self.assertEqual(parameters['rule_id'], 'disk-full')
        self.assertEqual(parameters['artifact_sha256'], 'a' * 64, 'a 64-char digest is a label, not prose')
        self.assertEqual(parameters['note'], 'one line')
        self.assertEqual(parameters['log_line'], policy.FREE_TEXT_PLACEHOLDER)
        self.assertEqual(counts, {'no_free_text': 1})
        # The point of two steps, stated as an assertion: a short value is a label to this step, so a
        # password written as `hunter2` survives `no_free_text` and only `secret_keys` removes it.
        self.assertEqual(parameters['password'], 'hunter2')

    def test_a_bare_string_is_redacted_too_because_the_instruction_is_data(self):
        prose, counts = policy.redact('please explain the incident, in detail, at some length: '
                                      + 'y' * 200, ['no_free_text'])
        self.assertEqual(prose, policy.FREE_TEXT_PLACEHOLDER)
        self.assertEqual(counts, {'no_free_text': 1})
        short, untouched = policy.redact('why is this host out of disk?', ['no_free_text'])
        self.assertEqual(short, 'why is this host out of disk?')
        self.assertEqual(untouched, {'no_free_text': 0})

    def test_steps_apply_in_order_and_an_unknown_step_refuses(self):
        scrubbed, counts = policy.redact(self.BUNDLE, ['secret_keys', 'no_free_text'])
        self.assertEqual(counts, {'secret_keys': 1, 'no_free_text': 1})
        self.assertEqual(scrubbed[0]['parameters']['password'], policy.REDACTED_PLACEHOLDER,
                         'the placeholder is short, so the second step leaves the first one alone')
        with self.assertRaises(PolicyError):
            policy.redact(self.BUNDLE, ['teleport'])


if __name__ == '__main__':
    unittest.main()
