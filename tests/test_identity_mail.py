"""The identity mail collector: the bounded Gmail-identity-alert parser, its trust gate and its collector, offline.

Every message here is synthetic. The sender domains are RFC 2606 names (`accounts.example`,
`collector.example`, `forward.example`, `phish.example`) and the *shipped* Google allowlist in
`providers.GOOGLE.trust` is never used as a fixture: the test policy names the reviewed lexicon by its
provider name (`google`) and points `sender_domains`/`dkim_domains` at the synthetic domains. So the real
Google lexicon patterns are exercised without encoding a live provider's addresses into a test, and the
question "would this classify a genuine Google alert?" is answered by the patterns, not by an address.

Nothing here opens a socket, and one test asserts that: `CollectorTests.test_no_network_path_is_reached`
runs a full tick with `socket.socket` and `socket.create_connection` replaced by raisers.

What is pinned, and the failure each one is guarding against:

* **The gate reads the attestation, never the header.** A message whose own `Authentication-Results`
  says `dkim=pass` with an allowlisted domain, and that carries no attestation, is `untrusted` — and the
  diagnostics say a forged header was seen. The reverse asymmetry is pinned too: an attestation that
  passes for these bytes is *not* overturned by a contradictory forged header, because the digest binding
  is the authority and a verdict that fluctuated with attacker text would be no gate at all.
* **Belief is bound to bytes.** The attestation must name the `sha256` of the level it vouches for. An
  attestation carried over from another message — the shape of a real replay — is
  `attestation-binding-mismatch`.
* **Nesting needs per-level attestation.** A forwarded alert (`message/rfc822`) is believed only when
  each level is attested for its own bytes *and* the container's signer is an allowlisted forwarder.
  `arc=pass` alone never opens the gate: it is recorded as a diagnostic, and the reason is in the unit
  document.
* **Content stops at the gate.** An untrusted message is refused before its subject or body is read, so
  `SecurityAlert` cannot exist for it, and its `diagnostics`/`code`/`reasons` never carry field text.
  Asserted by feeding a subject containing a marker string and searching the whole outcome, and the
  events built from the healthy path, for that marker.
* **Every malformed shape lands in a counted category.** Missing/duplicated identity headers, a
  colon-free line, an undecodable encoded-word `From`, a base64-encoded nested message, a missing
  boundary, an oversized blob, a message dated in the future. `None` of them raises out of
  `parse_message`, and `None` of them is silently `event`.
* **The collector bounds reads and survives a sink.** Reads stop at `max_messages` and `max_tick_bytes`
  and say `truncated`; the batch is on disk before the sink sees it; a failing sink leaves the pending
  batch *and* the cursor, and the next tick replays before reading; a transport failure files firing
  coverage without pretending a read completed (`last_success_at` unmoved). The pending entry is the
  read's whole *commit intent* — cursor position reached, mailbox generation digest, tally, and whether
  the read completed — so a replay lands the same source/cursor transition a first delivery would have,
  stamped with the observation time and never with the retry time. A pending batch behind the cursor
  without a generation change, one that would move the cursor without a completed read, an edited
  generation, or a pending record missing the source facts (the pre-binding shape) is refused: nothing
  is migrated or discarded silently.
* **The events are the product's own.** Each one passes `state.validate_event` against a real `now`,
  the batch's JSON contains no address, subject, body or mailbox-generation token, and a coverage
  verdict *change* is a new event rather than a same-id retry the store would refuse (`Store.intake`
  keys on `source_event_id`, which carries no `status`).

Not claimed anywhere in this file: live Gmail authentication, live IMAP collection, a real DKIM
verification, or any provider template beyond Google. Those are the open items listed in
`docs/units/identity-mail.md`.
"""
from datetime import datetime, timedelta, timezone
from email import policy as email_policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.identity_mail import collector, events, parser, providers, rfc822, trust
from local_observe.inventory.validation import canonical, digest, utc_text
from local_observe.platform.intake import Prepared
from local_observe.platform.state import StateError, validate_event

NOW = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
SENT = datetime(2026, 9, 22, 11, 55, 0, tzinfo=timezone.utc)
SENT_TEXT = 'Tue, 22 Sep 2026 11:55:00 +0000'
MARKER = 'MARKER-SUBJECT-TEXT-5c91'

AUTH_TEXT = '1; dkim=pass header.d=accounts.example header.s=k1 header.b=abcY; spf=pass ' \
            '(smtp.example: domain of accounts.example designates mail) smtp.mailfrom=accounts.example'

POLICY_DOCUMENT = {'schema_version': 1,
                   'providers': [{'name': 'google', 'sender_domains': ['accounts.example'],
                                  'dkim_domains': ['accounts.example', 'example.org']}],
                   'trusted_receivers': ['collector-mx'],
                   'forwarder_dkim_domains': ['forward.example']}

WIDE_FORWARDER_DOCUMENT = dict(POLICY_DOCUMENT, forwarder_dkim_domains=['forward.example',
                                                                       'accounts.example'])
WIDE_FORWARDER_POLICY = trust.policy_from_document(WIDE_FORWARDER_DOCUMENT)


def policy(document=None):
    """The shared trust policy, accepting either a document or an already-validated policy."""
    if isinstance(document, trust.TrustPolicy):
        return document
    return trust.policy_from_document(POLICY_DOCUMENT if document is None else document)


def alert(subject='A new sign-in on your Google Account', sender='no-reply@accounts.example',
          message_id='<alert-1@accounts.example>', stamp=SENT_TEXT, extra='', body=None,
          auth=AUTH_TEXT, content_type='text/plain; charset="utf-8"'):
    """One genuine-shaped provider alert, as top-level mail, with the receiver's own header inside it."""
    body = body or 'A new sign-in on your Google Account\r\nWindows device\r\n'
    return (f'Delivered-To: collector@collector.example\r\n'
            f'Authentication-Results: {auth}\r\n'
            f'{extra}'
            f'Message-ID: {message_id}\r\n'
            f'From: Google Account Support <{sender}>\r\n'
            f'To: operator@collector.example\r\n'
            f'Date: {stamp}\r\n'
            f'Subject: {subject}\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: {content_type}\r\n'
            f'\r\n{body}').encode()


def attestation(raw, results=AUTH_TEXT, receiver='collector-mx', channel='receiver-log',
                observed=None, digest_bytes=None):
    return trust.Attestation(receiver=receiver, levels=(trust.LevelAttestation(
        digest_sha256=hashlib.sha256(raw if digest_bytes is None else digest_bytes).hexdigest(),
        auth_results=results, channel=channel,
        observed_at=(SENT + timedelta(minutes=1) if observed is None else observed).isoformat()),))


def parse(raw, attestation=None, when=NOW, document=None):
    return parser.parse_message(raw, attestation=attestation, policy=policy(document), now=when)


def nested(inner, boundary='B1X', forwarder='forward@forward.example', encoding=None,
           auth='1; dkim=pass header.d=forward.example header.s=f1 header.b=def; arc=pass'):
    """A forwarding wrapper: multipart note plus the original alert as `message/rfc822`."""
    cte = '' if encoding is None else f'Content-Transfer-Encoding: {encoding}\r\n'
    return (f'Received: from mail.example (mail.example [192.0.2.1]) by collector.example\r\n'
            f'Authentication-Results: {auth}\r\n'
            f'Message-ID: <wrapper-1@forward.example>\r\n'
            f'From: Mailings <{forwarder}>\r\n'
            f'To: collector@collector.example\r\n'
            f'Date: Tue, 22 Sep 2026 11:56:00 +0000\r\n'
            f'Subject: Fwd: your Google Account\r\n'
            f'MIME-Version: 1.0\r\n'
            f'Content-Type: multipart/mixed; boundary="{boundary}"\r\n'
            f'\r\n--{boundary}\r\nContent-Type: text/plain\r\n'
            f'\r\nsee attached\r\n'
            f'--{boundary}\r\nContent-Type: message/rfc822\r\n{cte}'
            f'\r\n').encode() + inner + f'\r\n--{boundary}--\r\n'.encode()


def level_bytes(raw):
    """The embedded message's own bytes at the deepest level, as the boundary document defines them."""
    return max(rfc822.read_message(raw).chains, key=len)[-1].raw


def chain_attestations(raw, document=None, receiver='collector-mx'):
    """One attestation per message level the reader enumerates, each bound to that level's own bytes.

    This is the shape a real boundary would have to produce: a verifier that can attest the inner
    message, not just the envelope. The deepest level is treated as the provider alert and the ones
    above it as forwarders, so the fixture policy's forwarder list has to name them.
    """
    chain = max(rfc822.read_message(raw).chains, key=len)
    moment = (SENT + timedelta(minutes=1)).isoformat()
    last = len(chain) - 1
    return trust.Attestation(receiver=receiver, levels=tuple(
        trust.LevelAttestation(
            digest_sha256=hashlib.sha256(node.raw).hexdigest(),
            auth_results=(AUTH_TEXT if position == last else
                          '1; dkim=pass header.d=forward.example header.s=f1 header.b=def'),
            channel='receiver-log', observed_at=moment)
        for position, node in enumerate(chain)))


def two_level(raw, inner_results=AUTH_TEXT, outer_results=None, forwarder='forward.example'):
    """A container attestation plus an inner one, both bound to the bytes the reader hashes."""
    outer = outer_results if outer_results is not None else (
        f'1; dkim=pass header.d={forwarder} header.s=f1 header.b=def; arc=pass')
    inner = level_bytes(raw)
    moment = (SENT + timedelta(minutes=1)).isoformat()
    return trust.Attestation(receiver='collector-mx', levels=(
        trust.LevelAttestation(digest_sha256=hashlib.sha256(raw).hexdigest(), auth_results=outer,
                               channel='receiver-log', observed_at=moment),
        trust.LevelAttestation(digest_sha256=hashlib.sha256(inner).hexdigest(),
                               auth_results=inner_results, channel='receiver-log', observed_at=moment)))


# ------------------------------------------------------------------ the RFC 8601 field itself


class AuthenticationResultsParsing(unittest.TestCase):
    def test_genuine_field_parses_with_comment_and_semicolons(self):
        statements = trust.parse_authentication_results(AUTH_TEXT)
        self.assertIsNotNone(statements)
        self.assertEqual([item.mechanism for item in statements], ['dkim', 'spf'])
        dkim = statements[0]
        self.assertEqual(dkim.result, 'pass')
        self.assertEqual(dkim.properties['header.d'], 'accounts.example')
        # The SPF comment carried spaces, an equals-shaped phrase and a domain: none of it leaked into
        # a property, which is the only reason to strip comments before splitting rather than after.
        self.assertEqual(statements[1].properties['smtp.mailfrom'], 'accounts.example')

    def test_quoted_property_value_survives_semicolon_and_space(self):
        statements = trust.parse_authentication_results(
            '1; dkim=pass header.d="a.example" header.i="smtp; out 4.99" header.b=z')
        self.assertEqual(len(statements), 1, 'a quoted semicolon does not end a statement')
        self.assertEqual(statements[0].properties['header.i'], 'smtp; out 4.99')
        self.assertEqual(statements[0].properties['header.d'], 'a.example')

    def test_malformed_and_hostile_fields_return_none_not_an_exception(self):
        deep = '1; dkim=pass ' + '(a' * 40
        wide = '1; dkim=pass ' + 'a=b ' * 40
        for text in ('', '   ', '1; ', '(unbalanced', deep, '9; dkim=pass header.d=a.example',
                     'unknownmech=pass header.d=a.example', 'dkim=maybe header.d=a.example',
                     'dkim=pass header.d=' + 'x' * 400, wide, 'x' * 5000, '"unclosed'):
            self.assertIsNone(trust.parse_authentication_results(text), f'{text[:24]!r} parses')

    def test_trailing_separators_are_tolerated_because_receivers_emit_them(self):
        statements = trust.parse_authentication_results('1; dkim=pass header.d=a.example; ; ;')
        self.assertEqual(len(statements), 1)

    def test_a_field_without_the_version_prefix_still_parses(self):
        # Real receivers write both shapes, and the version buys nothing this gate relies on.
        statements = trust.parse_authentication_results('dkim=pass header.d=accounts.example')
        self.assertEqual(statements[0].result, 'pass')

    def test_unknown_mechanism_parses_and_cannot_open_anything(self):
        statements = trust.parse_authentication_results('1; mia=pass header.d=accounts.example')
        self.assertEqual(statements[0].mechanism, 'mia')
        claims = '1; mia=pass header.d=accounts.example'
        raw = alert()
        outcome = parse(raw, attestation(raw, results=claims))
        self.assertEqual((outcome.classification, outcome.code), ('untrusted', 'dkim-record-absent'))


# ------------------------------------------------------------------------- the trust gate


class TrustGateTests(unittest.TestCase):
    def setUp(self):
        self.raw = alert()
        self.assessment = trust.assess(attestation=attestation(self.raw), policy=policy(),
                                       levels=(trust.Level(digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                                           sender_domain='accounts.example',
                                                           header_auth_results=(AUTH_TEXT,)),),
                                       provider=policy().providers[0], now=NOW)

    def test_genuine_attestation_opens_the_gate(self):
        self.assertTrue(self.assessment.trusted)
        self.assertEqual(self.assessment.code, 'trusted')
        self.assertEqual(self.assessment.diagnostics, ())

    def test_no_attestation_means_no_belief_whatever_the_headers_say(self):
        assessment = trust.assess(attestation=None, policy=policy(),
                                  levels=(trust.Level(digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                                      sender_domain='accounts.example'),),
                                  provider=policy().providers[0], now=NOW)
        self.assertEqual((assessment.trusted, assessment.code), (False, 'attestation-absent'))

    @mock.patch('local_observe.identity_mail.trust._dkim_verdict', side_effect=AssertionError('unused'))
    def test_receiver_outside_the_policy_is_refused_before_any_header_is_parsed(self, verdict):
        assessment = trust.assess(attestation=attestation(self.raw, receiver='someone-else'),
                                  policy=policy(), levels=(trust.Level(
                                      digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                      sender_domain='accounts.example'),),
                                  provider=policy().providers[0], now=NOW)
        self.assertEqual((assessment.trusted, assessment.code), (False, 'receiver-untrusted'))
        verdict.assert_not_called()

    def test_attestation_for_other_bytes_is_refused(self):
        other = attestation(self.raw, digest_bytes=alert(message_id='<other@accounts.example>'))
        assessment = trust.assess(attestation=other, policy=policy(),
                                  levels=(trust.Level(digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                                      sender_domain='accounts.example'),),
                                  provider=policy().providers[0], now=NOW)
        self.assertEqual((assessment.trusted, assessment.code), (False, 'attestation-binding-mismatch'))

    def test_stale_and_future_attestations_are_refused(self):
        document = dict(POLICY_DOCUMENT, max_attestation_age_seconds=600)
        for moment, code in ((NOW - timedelta(days=2), 'attestation-stale'),
                             (NOW + timedelta(minutes=30), 'attestation-from-the-future')):
            raw = self.raw
            assessment = trust.assess(attestation=attestation(raw, observed=moment), policy=policy(document),
                                      levels=(trust.Level(
                                          digest_sha256=hashlib.sha256(raw).hexdigest(),
                                          sender_domain='accounts.example'),),
                                      provider=policy(document).providers[0], now=NOW)
            self.assertEqual((assessment.trusted, assessment.code), (False, code), code)

    def test_unreadable_attestation_text_is_refused_not_guessed(self):
        assessment = trust.assess(attestation=attestation(self.raw, results='1; dkim=maybe'),
                                  policy=policy(), levels=(trust.Level(
                                      digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                      sender_domain='accounts.example'),),
                                  provider=policy().providers[0], now=NOW)
        self.assertEqual((assessment.trusted, assessment.code), (False, 'attestation-malformed'))

    def test_a_trusted_channel_list_is_closed_and_narrowable_only(self):
        with self.assertRaises(trust.AttestationError):
            trust.LevelAttestation(digest_sha256=hashlib.sha256(b'x').hexdigest(), auth_results=AUTH_TEXT,
                                   channel='imap-header', observed_at=SENT.isoformat())
        with self.assertRaises(trust.AttestationError):
            trust.TrustPolicy(providers=policy().providers, trusted_receivers=('collector-mx',),
                              channels=('carrier-pigeon',))
        narrow = trust.TrustPolicy(providers=policy().providers, trusted_receivers=('collector-mx',),
                                   channels=('provider-api',))
        assessment = trust.assess(attestation=attestation(self.raw), policy=narrow,
                                  levels=(trust.Level(digest_sha256=hashlib.sha256(self.raw).hexdigest(),
                                                      sender_domain='accounts.example'),),
                                  provider=policy().providers[0], now=NOW)
        self.assertEqual((assessment.trusted, assessment.code), (False, 'channel-untrusted'))

    def test_policy_document_refuses_stray_keys_empty_lists_and_bad_domains(self):
        for document in ({'schema_version': 2, 'providers': POLICY_DOCUMENT['providers'],
                          'trusted_receivers': ['collector-mx']},
                         dict(POLICY_DOCUMENT, unknown='x'),
                         dict(POLICY_DOCUMENT, providers=[]),
                         dict(POLICY_DOCUMENT, trusted_receivers=[]),
                         dict(POLICY_DOCUMENT, forwarder_dkim_domains=['not a domain']),
                         dict(POLICY_DOCUMENT, max_attestation_age_seconds=5),
                         {'schema_version': 1, 'providers': [{'name': 'google'}],
                          'trusted_receivers': ['collector-mx']}):
            with self.assertRaises(trust.AttestationError):
                trust.policy_from_document(document)

    def test_sender_lookup_is_exact_not_suffix_or_substring(self):
        chosen = policy()
        self.assertIsNone(chosen.provider_for_sender('accounts.example.phish.example'))
        self.assertIsNone(chosen.provider_for_sender('example'))
        self.assertIsNotNone(chosen.provider_for_sender('ACCOUNTS.EXAMPLE.'))

    def test_policy_fingerprint_ignores_document_formatting_and_tracks_content(self):
        same = dict(POLICY_DOCUMENT, providers=[dict(POLICY_DOCUMENT['providers'][0])])
        self.assertEqual(trust.policy_fingerprint(policy()), trust.policy_fingerprint(policy(same)))
        widened = dict(POLICY_DOCUMENT, providers=[dict(POLICY_DOCUMENT['providers'][0],
                                                       dkim_domains=['accounts.example', 'evil.example'])])
        self.assertNotEqual(trust.policy_fingerprint(policy()), trust.policy_fingerprint(policy(widened)))


# ----------------------------------------------------------------------- structural reading


class StructuralReadingTests(unittest.TestCase):
    def test_header_field_counts_are_ours_and_dupe_detection_needs_them(self):
        document = rfc822.read_message(alert(extra='X-Loop: 1\r\nX-Loop: 2\r\n'))
        self.assertEqual(document.root.values('x-loop'), ('1', '2'))
        probe = BytesParser(policy=email_policy.compat32).parsebytes(document.root.raw)
        self.assertEqual(len(document.root.headers), len(probe.items()),
                         'duplicate counting needs the same field count as the stdlib reader')

    def test_folded_fields_are_one_field(self):
        raw = alert(extra='Received: from a.example\r\n by b.example id 7;\r\n\tTue, 22 Sep 2026 '
                          '11:50:00 +0000\r\nX-Other: 1\r\n')
        document = rfc822.read_message(raw)
        self.assertEqual(len(document.root.values('received')), 1)

    def test_nested_multipart_yields_two_message_levels_and_exact_inner_bytes(self):
        raw = nested(alert(message_id='<inner-9@accounts.example>'))
        document = rfc822.read_message(raw)
        chains = sorted(document.chains, key=len)
        self.assertEqual([len(chain) for chain in chains], [1, 2],
                         'the wrapper chain and the forwarded-alert chain, nothing invented')
        deepest = chains[-1]
        self.assertEqual(deepest[-1].first('message-id'), '<inner-9@accounts.example>')
        self.assertIn(b'A new sign-in on your Google Account', deepest[-1].raw)
        self.assertIn(b'Message-ID: <inner-9@accounts.example>', deepest[-1].raw)
        self.assertEqual(deepest[-1].depth, 1)

    def test_a_forwarded_level_digest_survives_a_rebuild_of_the_same_bytes(self):
        raw = nested(alert(message_id='<inner-9@accounts.example>'))
        inner = level_bytes(raw)
        self.assertEqual(hashlib.sha256(inner).hexdigest(),
                         hashlib.sha256(level_bytes(raw)).hexdigest())
        self.assertNotIn(b'--B1X', inner, 'the container\'s delimiter is not part of the level')
        self.assertFalse(inner.endswith(b'\r\n\r\n'), 'one delimiter CRLF, not the message\'s own')

    def test_transfer_encoded_nested_message_is_refused_rather_than_reassembled(self):
        import base64
        inner = alert(message_id='<inner-b64@accounts.example>')
        wrapped = nested(base64.b64encode(inner), encoding='base64')
        with self.assertRaises(rfc822.StructuralRefusal) as caught:
            rfc822.read_message(wrapped)
        self.assertEqual(caught.exception.code, 'transfer-encoded-nested')

    def test_malformed_shapes_refuse_with_one_code_each(self):
        # The `bad-boundary` and `malformed-multipart` fixtures are refused as `malformed-headers`:
        # the stdlib cross-check inspects the whole level and reports the missing start boundary
        # before this reader's own multipart rules run. The expectation is the measured code, and the
        # boundary rules themselves are proved directly below, where they actually run.
        expected = {'bad-boundary': 'malformed-headers',
                    'malformed-multipart': 'malformed-headers'}
        cases = {'malformed-headers': b'From: a@b.example\r\nno colon here\r\n\r\nx',
                 'empty-message': b'',
                 'not-bytes': 'From: a@b.example\r\n\r\n',
                 # A multipart body the boundary rules would refuse is already refused by the
                 # independent reader one step earlier, so the code an operator sees is the earlier
                 # one. Both readings refuse; the strictness is the point, not which name prints.
                 'bad-boundary': (b'Message-ID: <1@b.example>\r\nFrom: a@b.example\r\n'
                                  b'Date: Tue, 22 Sep 2026 11:55:00 +0000\r\n'
                                  b'Content-Type: multipart/mixed\r\n\r\nnothing'),
                 # A multipart body with no delimiter is refused by the independent reader before the
                 # boundary rules are reached; both readings refuse, and the earlier one names itself.
                 'malformed-multipart': (b'Message-ID: <1@b.example>\r\nFrom: a@b.example\r\n'
                                         b'Date: Tue, 22 Sep 2026 11:55:00 +0000\r\n'
                                         b'Content-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
                                         b'no delimiter here'),
                 'duplicate-content-type': alert(content_type='text/plain') + b'',
                 'oversized-message': b'From: a@b.example\r\n\r\n' + b'x' * rfc822.MAX_MESSAGE_BYTES}
        cases['duplicate-content-type'] = (b'Message-ID: <1@accounts.example>\r\n'
                                          b'Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\nx')
        for code, raw in cases.items():
            with self.subTest(code=code):
                with self.assertRaises(rfc822.StructuralRefusal) as caught:
                    rfc822.read_message(raw)
                self.assertEqual(caught.exception.code, expected.get(code, code))

    def test_the_boundary_rules_are_reachable_directly(self):
        # The stdlib cross-check refuses a broken multipart before these rules are reached, so the
        # rules that still exist have to be proved where they actually run: on a delimiter scan.
        self.assertEqual(rfc822._boundary({'boundary': 'ok-boundary'}), 'ok-boundary')
        for parameters in ({}, {'boundary': ''}, {'boundary': 'x' * 71}, {'boundary': 'trailing '},
                           {'boundary': 'bad*char'}):
            with self.assertRaises(rfc822.StructuralRefusal) as caught:
                rfc822._boundary(parameters)
            self.assertEqual(caught.exception.code, 'bad-boundary')
        parts = rfc822._multipart(b'--BB\r\nfirst\r\n--BB\r\nsecond\r\n--BB--\r\n', 'BB')
        self.assertEqual(parts, [b'first', b'second'])
        with self.assertRaises(rfc822.StructuralRefusal):
            rfc822._multipart(b'--BB\r\nonly\r\n', 'BB'), 'a tree with no closing delimiter'
        with self.assertRaises(rfc822.StructuralRefusal) as caught:
            rfc822._multipart(b'nothing here', 'BB')
        self.assertEqual(caught.exception.code, 'malformed-multipart')

    def test_refusal_carries_no_message_text(self):
        raw = b'From: secret-name@victim.example\r\nno-colon-line-that-must-not-leak\r\n\r\nbody'
        with self.assertRaises(rfc822.StructuralRefusal) as caught:
            rfc822.read_message(raw)
        self.assertNotIn('secret-name', str(caught.exception))
        self.assertEqual(caught.exception.code, 'malformed-headers')

    def test_part_count_is_bounded(self):
        parts = b''.join(b'--BB\r\nContent-Type: text/plain\r\n\r\np\r\n' for _ in range(40))
        raw = (b'Message-ID: <1@accounts.example>\r\nFrom: a@accounts.example\r\n'
               b'Date: Tue, 22 Sep 2026 11:55:00 +0000\r\n'
               b'Content-Type: multipart/mixed; boundary="BB"\r\n\r\n' + parts + b'--BB--\r\n')
        with self.assertRaises(rfc822.StructuralRefusal) as caught:
            rfc822.read_message(raw)
        self.assertEqual(caught.exception.code, 'too-many-parts')

    def test_collect_text_prefers_plain_and_reports_truncation(self):
        raw = (b'Message-ID: <1@accounts.example>\r\nFrom: a@accounts.example\r\n'
               b'Date: Tue, 22 Sep 2026 11:55:00 +0000\r\nSubject: hello\r\n'
               b'Content-Type: multipart/alternative; boundary="AA"\r\n\r\n'
               b'--AA\r\nContent-Type: text/html\r\n\r\n<html>plain-beats-this</html>\r\n'
               b'--AA\r\nContent-Type: text/plain\r\n\r\nthe plain part\r\n--AA--\r\n')
        subject, texts, skipped = rfc822.collect_text(rfc822.read_message(raw).root)
        self.assertEqual(subject, 'hello')
        self.assertEqual(texts, ('the plain part\n',) if texts[0].endswith('\n') else ('the plain part',))
        self.assertNotIn('plain-beats-this', ''.join(texts))
        self.assertEqual(skipped, 0)
        short_subject, short_texts, short_skipped = rfc822.collect_text(
            rfc822.read_message(raw).root, limit=4)
        self.assertLessEqual(sum(len(item) for item in short_texts), 4)
        self.assertEqual(short_subject, 'hell')
        self.assertGreaterEqual(short_skipped, 1, 'a bounded read says it was bounded')


# --------------------------------------------------------------- the classification pipeline


class ClassificationTests(unittest.TestCase):
    def test_genuine_alert_with_attestation_becomes_a_structured_event(self):
        raw = alert()
        outcome = parse(raw, attestation(raw))
        self.assertEqual((outcome.classification, outcome.code), ('event', 'classified'))
        self.assertEqual(outcome.provider, 'google')
        self.assertEqual(outcome.levels, 1)
        self.assertEqual(outcome.diagnostics, ())
        alert_ = outcome.alert
        self.assertEqual(alert_.alert_type, 'signin-new-device')
        self.assertEqual(alert_.occurred_at, '2026-09-22T11:55:00.000000+00:00')
        self.assertEqual(alert_.sender_domain, 'accounts.example')
        self.assertEqual(len(alert_.message_identity), 64)
        self.assertNotIn('@', json.dumps(alert_.__dict__) + str(alert_.account_hint))

    def test_each_recognised_google_alert_type_is_classified_not_guessed(self):
        cases = {'A new sign-in on your Google Account': 'signin-new-device',
                 'Failed sign-in attempt to your Google Account': 'signin-failed',
                 'Your Google Account password was changed': 'password-changed',
                 'Your recovery email was added to your Google Account': 'recovery-info-changed',
                 '2-step verification was turned off on your Google Account': 'two-step-changed',
                 'All sign-in sessions have been revoked': 'session-revoked',
                 'Someone may have tried to sign in to your Google Account': 'signin-recent-activity',
                 'Important security warning for your Google Account': 'security-alert'}
        for subject, expected in cases.items():
            with self.subTest(subject=subject):
                # The body repeats the subject the way provider mail does; a fixture whose body always
                # said "new sign-in" would classify every type by its body and prove nothing.
                raw = alert(subject=subject, body=subject + '\r\nDetails below.\r\n')
                outcome = parse(raw, attestation(raw))
                self.assertEqual(outcome.classification, 'event', outcome.code)
                self.assertEqual(outcome.alert.alert_type, expected)

    def test_the_specific_type_wins_over_the_generic_bucket(self):
        raw = alert(subject='Security alert: failed sign-in attempt on your Google Account')
        outcome = parse(raw, attestation(raw))
        self.assertEqual(outcome.alert.alert_type, 'signin-failed')

    def test_forged_authentication_header_without_attestation_is_untrusted(self):
        forged = '1; dkim=pass header.d=accounts.example header.s=k1 header.b=forged'
        raw = alert(extra=f'Authentication-Results: {forged}\r\n', auth='1; dkim=none')
        outcome = parse(raw)
        self.assertEqual((outcome.classification, outcome.code), ('untrusted', 'attestation-absent'))
        self.assertIsNone(outcome.alert)
        self.assertIn('authentication-header-claims-dkim-pass', outcome.diagnostics)
        self.assertIn('authentication-header-observed', outcome.diagnostics)

    def test_forged_header_disagreeing_with_the_receiver_is_reported_not_believed(self):
        raw = alert(extra='Authentication-Results: 1; dkim=pass header.d=evil.example header.s=k1\r\n',
                    auth='1; spf=none')
        outcome = parse(raw, attestation(raw))
        self.assertEqual(outcome.classification, 'event')
        self.assertIn('receiver-copy-differs-from-message', outcome.diagnostics)
        self.assertIn('forged-authentication-header-observed', outcome.diagnostics)

    def test_an_arc_failure_is_reported_and_does_not_change_a_dkim_verdict(self):
        """ARC is a chain seal, not this gate's authority: recorded, never believed or distrusted.

        Belief here is a DKIM verdict bound to the bytes in hand, so an `arc=fail` on a directly
        delivered alert changes the diagnostics an operator sees and not the verdict. The opposite
        reading — treating `arc=pass` as a substitute for a bound inner verdict — is refused elsewhere
        (`forwarder-not-trusted`), which is where the risk actually lives.
        """
        auth = '1; dkim=pass header.d=accounts.example header.s=k1 header.b=abcY; arc=fail'
        raw = alert(auth=auth)
        outcome = parse(raw, attestation(raw, results=auth))
        self.assertEqual(outcome.classification, 'event')
        self.assertIn('arc-fail', outcome.diagnostics)

    def test_wrong_dkim_domain_and_misalignment_are_both_refused(self):
        raw = alert()
        for results, code in (('1; dkim=pass header.d=evil.example header.s=k1',
                               'dkim-domain-not-allowlisted'),
                              ('1; dkim=pass header.d=example.org header.s=k1', 'dkim-misaligned'),
                              ('1; dkim=fail header.d=accounts.example', 'dkim-not-pass'),
                              ('1; dkim=pass header.d=accounts.example; dmarc=fail '
                               'header.from=accounts.example', 'dmarc-refused'),
                              ('1; dkim=pass header.d=accounts.example; dmarc=permerror',
                               'dmarc-refused'),

                              ('1; dkim=pass header.d=accounts.example; spf=fail', 'spf-refused'),
                              ('1; spf=pass smtp.mailfrom=accounts.example', 'dkim-record-absent')):
            with self.subTest(results=results):
                outcome = parse(raw, attestation(raw, results=results))
                self.assertEqual((outcome.classification, outcome.code), ('untrusted', code))

    def test_a_phishing_sender_domain_is_out_of_scope_and_not_a_parse_failure(self):
        raw = alert(sender='security@accounts.example.phish.example')
        outcome = parse(raw, attestation(raw))
        self.assertEqual((outcome.classification, outcome.code), ('unsupported', 'sender-domain-unknown'))
        self.assertIsNone(outcome.alert)

    def test_missing_identity_fields_are_parse_failures(self):
        for name, code in (('message-id', 'missing-message-id'), ('from', 'missing-from'),
                           ('date', 'missing-date')):
            with self.subTest(field=name):
                raw = alert().split(b'\r\n')
                kept = b'\r\n'.join(line for line in raw if not line.lower().startswith(name.encode()))
                outcome = parse(kept, attestation(kept))
                self.assertEqual((outcome.classification, outcome.code), ('parse-failure', code))

    def test_duplicated_identity_headers_are_refused_not_resolved_by_order(self):
        for extra, code in (('Message-ID: <dupe@accounts.example>\r\n', 'duplicate-message-id'),
                            ('From: Second <two@accounts.example>\r\n', 'duplicate-from'),
                            ('Date: Tue, 22 Sep 2026 11:54:00 +0000\r\n', 'duplicate-date')):
            with self.subTest(code=code):
                raw = alert(extra=extra)
                outcome = parse(raw, attestation(raw))
                self.assertEqual((outcome.classification, outcome.code), ('parse-failure', code))

    def test_duplicate_authentication_headers_are_counted_and_the_gate_still_decides(self):
        raw = alert(extra='Authentication-Results: 1; dkim=none header.d=nope.example\r\n')
        outcome = parse(raw, attestation(raw))
        self.assertEqual(outcome.classification, 'event')
        self.assertIn('multiple-authentication-headers', outcome.diagnostics)

    def test_oversized_input_is_refused_before_any_parsing(self):
        raw = alert() + b'\r\n' + b'x' * rfc822.MAX_MESSAGE_BYTES
        with mock.patch('local_observe.identity_mail.rfc822.read_message',
                        side_effect=AssertionError('must not be called')) as reader:
            outcome = parse(raw, attestation(raw))
        reader.assert_not_called()
        self.assertEqual((outcome.classification, outcome.code), ('parse-failure', 'oversized-message'))
        self.assertEqual(outcome.bytes_read, 0)

    def test_malformed_body_and_headers_never_raise_out_of_the_parser(self):
        for raw in (b'From: a@accounts.example\r\nno-colon-line\r\n\r\nbody',
                    b'From: =?bogus?B?...?= <a@accounts.example>\r\n\r\nx',
                    alert(subject='=?utf-8?B?c2lnbi1pbg==?=', message_id='<enc@accounts.example>'),
                    b'Content-Type: multipart/mixed; boundary="A"\r\nFrom: a@accounts.example\r\n\r\n--A',
                    alert(message_id='<x' * 200 + '>')):
            with self.subTest(raw=raw[:40]):
                outcome = parse(raw, attestation(raw))
                self.assertIn(outcome.classification, parser.CLASSIFICATIONS)
                self.assertIsInstance(outcome.code, str)
                self.assertIsInstance(outcome.bytes_read, int)

    def test_encoded_word_in_an_identity_header_is_refused(self):
        raw = alert(sender='=?utf-8?B?aW52YWxpZA==?=@accounts.example')
        outcome = parse(raw, attestation(raw))
        self.assertEqual((outcome.classification, outcome.code), ('parse-failure', 'encoded-identity-header'))

    def test_genuine_provider_mail_that_matches_no_pattern_is_unsupported(self):
        raw = alert(subject='Your weekly Google Account summary', body='Here is your month in review.')
        outcome = parse(raw, attestation(raw))
        self.assertEqual((outcome.classification, outcome.code), ('unsupported', 'alert-type-unrecognised'))

    def test_dates_outside_the_credible_range_are_refused(self):
        for stamp, code in (('Tue, 22 Sep 2026 12:30:00 +0000', 'date-in-the-future'),
                            ('Tue, 22 Sep 2026 11:55:00 -0000', 'date-without-timezone'),
                            ('yesterday-ish', 'bad-date'),
                            ('Mon, 1 Jan 2001 11:55:00 +0000', 'date-out-of-range')):
            with self.subTest(stamp=stamp):
                raw = alert(stamp=stamp)
                outcome = parse(raw, attestation(raw))
                self.assertEqual((outcome.classification, outcome.code), ('parse-failure', code))

    def test_untrusted_content_is_never_read_into_an_alert(self):
        raw = alert(subject='A new sign-in on your Google Account ' + MARKER)
        outcome = parse(raw)
        self.assertEqual(outcome.classification, 'untrusted')
        self.assertIsNone(outcome.alert)
        self.assertNotIn(MARKER, str(outcome))
        self.assertNotIn(MARKER, json.dumps({'code': outcome.code, 'diagnostics': outcome.diagnostics,
                                             'hint': outcome.sender_hint}))

    def test_body_marker_reaches_only_the_alert_and_never_an_event(self):
        raw = alert(body='A new sign-in on your Google Account\r\n' + MARKER + '\r\n')
        outcome = parse(raw, attestation(raw))
        self.assertEqual(outcome.classification, 'event')
        self.assertNotIn(MARKER, str(outcome.alert))
        self.assertNotIn(MARKER, json.dumps([dict(event) for event in events.events_for(outcome.alert)]))

    def test_nested_forwarded_alert_needs_both_levels_attested(self):
        raw = nested(alert(message_id='<inner-2@accounts.example>'))
        outcome = parse(raw, two_level(raw))
        self.assertEqual(outcome.classification, 'event')
        self.assertEqual(outcome.levels, 2)
        self.assertEqual(outcome.alert.alert_type, 'signin-new-device')
        self.assertIn('arc-pass', outcome.diagnostics)

    def test_nested_alert_with_one_outer_attestation_is_untrusted(self):
        raw = nested(alert(message_id='<inner-3@accounts.example>'))
        outcome = parse(raw, attestation(raw))
        self.assertEqual((outcome.classification, outcome.code), ('untrusted', 'attestation-level-count'))

    def test_nested_alert_behind_an_untrusted_forwarder_is_refused(self):
        document = dict(POLICY_DOCUMENT, forwarder_dkim_domains=[])
        raw = nested(alert(message_id='<inner-4@accounts.example>'))
        outcome = parse(raw, two_level(raw), document=document)
        self.assertEqual((outcome.classification, outcome.code), ('untrusted', 'forwarder-not-trusted'))

    def test_an_attackers_own_nested_fake_gets_no_belief(self):
        """A hand-written look-alike alert inside a signed wrapper: the inner bytes are not Google's."""
        fake = (b'Message-ID: <fake-1@accounts.example>\r\n'
                b'From: Google <security@accounts.example>\r\nTo: collector@collector.example\r\n'
                b'Date: Tue, 22 Sep 2026 11:55:00 +0000\r\n'
                b'Subject: A new sign-in on your Google Account\r\n'
                b'Content-Type: text/plain\r\n\r\nA new sign-in on your Google Account\r\n')
        raw = nested(fake)
        unsigned = parse(raw, two_level(raw, inner_results='1; dkim=fail header.d=accounts.example'))
        self.assertEqual((unsigned.classification, unsigned.code), ('untrusted', 'dkim-not-pass'))
        absent = parse(raw, two_level(raw, inner_results='1; spf=pass smtp.mailfrom=accounts.example'))
        self.assertEqual((absent.classification, absent.code), ('untrusted', 'dkim-record-absent'))
        bound_to_wrong_bytes = parse(raw, two_level(raw, inner_results=AUTH_TEXT),
                                    document=dict(POLICY_DOCUMENT, forwarder_dkim_domains=[]))
        self.assertEqual(bound_to_wrong_bytes.code, 'forwarder-not-trusted')

    def test_the_deepest_provider_message_wins_and_a_deeper_tie_still_decides(self):
        # A forwarder on the same provider is the common real shape: the wrapper's From is also a
        # supported domain, and the inner message is the alert. Deepest wins, by rule, not by list order.
        raw = nested(alert(message_id='<deep@accounts.example>'), forwarder='forward@accounts.example')
        outcome = parse(raw, two_level(raw, outer_results='1; dkim=pass header.d=accounts.example'),
                        document=WIDE_FORWARDER_POLICY)
        self.assertEqual(outcome.classification, 'event')
        self.assertEqual(outcome.levels, 2)
        self.assertEqual(outcome.alert.message_identity, trust.sha256_text(b'<deep@accounts.example>'))
        tied = nested(nested(alert(message_id='<two-deep@accounts.example>'), boundary='INNERB'),
                      boundary='OUTERB')
        deep = parse(tied, chain_attestations(tied))
        self.assertEqual(deep.classification, 'event', deep.code)
        self.assertEqual(deep.levels, 3)
        self.assertEqual(deep.alert.message_identity, trust.sha256_text(b'<two-deep@accounts.example>'))

    def test_parse_message_requires_a_real_clock(self):
        with self.assertRaises(ValueError):
            parser.parse_message(alert(), attestation=None, policy=policy(),
                                 now=datetime(2026, 9, 22, 12, 0, 0))

    def test_only_an_event_classification_may_carry_an_alert(self):
        with self.assertRaises(ValueError):
            parser.ParseOutcome(classification='untrusted', code='attestation-absent',
                                alert=parser.SecurityAlert(
                                    provider='google', alert_type='security-alert',
                                    occurred_at='2026-09-22T11:55:00.000000+00:00',
                                    message_identity='x', sender_domain='accounts.example',
                                    account_hint=None, level_count=1))


# ------------------------------------------------------------------------ the event boundary


class EventBoundaryTests(unittest.TestCase):
    def setUp(self):
        raw = alert()
        self.outcome = parse(raw, attestation(raw))

    def test_events_pass_the_stores_own_validator(self):
        built = events.events_for(self.outcome.alert, window_seconds=600)
        self.assertEqual(len(built), 1)
        validate_event(built[0], NOW)
        self.assertEqual(built[0]['kind'], 'security')
        self.assertEqual(built[0]['source'], 'identity-mail')
        self.assertEqual(built[0]['rule_id'], 'google.signin-new-device')
        self.assertEqual(built[0]['status'], 'firing')
        self.assertIsNone(built[0]['resource_id'])
        self.assertEqual(built[0]['evidence'][0]['query_type'], 'source-heartbeat')
        self.assertEqual(built[0]['evidence'][0]['parameters'], {'rule_id': 'google.signin-new-device'})

    def test_the_window_runs_backwards_from_the_mail_and_is_reproducible(self):
        first = events.events_for(self.outcome.alert)[0]
        second = events.events_for(self.outcome.alert)[0]
        self.assertEqual(canonical(first), canonical(second))
        start, end = first['window']['start'], first['window']['end']
        self.assertEqual(end, self.outcome.alert.occurred_at)
        self.assertLess(start, end)
        self.assertLessEqual(end, NOW.isoformat())

    def test_two_messages_of_one_type_in_one_second_fold_rather_than_collide(self):
        """Identical payloads must be byte-identical, or `Store.intake` answers a changed-contents 400."""
        first = parse(alert(message_id='<a@accounts.example>'),
                      attestation(alert(message_id='<a@accounts.example>')))
        same_second = alert(message_id='<different-id@accounts.example>', subject='New sign-in. '
                            'A new sign-in on your Google Account')
        second = parse(same_second, attestation(same_second))
        self.assertEqual((first.classification, second.classification), ('event', 'event'))
        built_first = canonical(events.events_for(first.alert)[0])
        built_second = canonical(events.events_for(second.alert)[0])
        self.assertEqual(built_first, built_second)

    def test_no_message_content_or_secret_shape_reaches_the_events(self):
        built = [dict(event) for event in events.events_for(self.outcome.alert)]
        payload = json.dumps(built)
        for fragment in ('accounts.example', 'operator@collector.example', 'sign-in on your',
                         'Google Account Support', 'collector-mx', MARKER, 'header.d'):
            self.assertNotIn(fragment, payload)
        for event in built:
            self.assertEqual(set(event['evidence'][0]['parameters']), {'rule_id'})

    def test_rule_ids_come_only_from_the_closed_vocabularies(self):
        alert_ = self.outcome.alert
        self.assertEqual(events.rule_for(alert_), 'google.signin-new-device')
        forged = parser.SecurityAlert(provider='evil', alert_type='security-alert',
                                      occurred_at=alert_.occurred_at, message_identity='x',
                                      sender_domain='accounts.example', account_hint=None, level_count=1)
        with self.assertRaises(StateError):
            events.rule_for(forged)
        weird = parser.SecurityAlert(provider='google', alert_type='do-something-dangerous',
                                     occurred_at=alert_.occurred_at, message_identity='x',
                                     sender_domain='accounts.example', account_hint=None, level_count=1)
        with self.assertRaises(StateError):
            events.rule_for(weird)

    def test_coverage_events_are_bounded_and_only_three_rules_exist(self):
        for rule in events.COVERAGE_RULES:
            built = events.coverage_event(rule, firing=True, now=NOW, window_seconds=300)
            validate_event(built, NOW)
            self.assertEqual(built['kind'], 'coverage')
            same_tick = events.coverage_event(rule, firing=True, now=NOW, window_seconds=300)
            self.assertEqual(canonical(built), canonical(same_tick),
                             'a replayed batch must be byte-identical or intake refuses it')
            start, end = built['window']['start'], built['window']['end']
            self.assertEqual(end, utc_text(NOW), 'the window names this tick, not a bucket')
            self.assertEqual(start, utc_text(NOW - timedelta(seconds=300)),
                             'the 300 s is the span claimed, not the identity')
            resolved = events.coverage_event(rule, firing=False, now=NOW, window_seconds=300)
            self.assertEqual(resolved['status'], 'resolved')
        with self.assertRaises(StateError):
            events.coverage_event('identity-mail.google.signin-new-device', firing=True, now=NOW)

    def test_a_coverage_recovery_is_a_new_event_and_not_a_changed_contents_retry(self):
        """`Store.intake` keys an event on source + `source_event_id`, and `detections.event` derives that
        id from [rule_id, rule_version, resource_id, window] — never from `status`. A `firing` coverage
        event and the `resolved` event that replaces it inside one evaluation window are therefore the
        same event to the store, and the second one is refused as `Event retry changed contents`: the
        batch stays pending, replays forever, and the cursor stops. Each event taken alone passes
        `validate_event`, so nothing else in this file would notice.
        """
        firing = events.coverage_event(events.PARSE_COVERAGE_RULE, firing=True, now=NOW)
        recovered = events.coverage_event(events.PARSE_COVERAGE_RULE, firing=False,
                                         now=NOW + timedelta(seconds=90))
        self.assertEqual(firing['rule_id'], recovered['rule_id'])
        self.assertEqual(firing['status'], 'firing')
        self.assertEqual(recovered['status'], 'resolved')
        self.assertNotEqual(firing['source_event_id'], recovered['source_event_id'])
        self.assertLess(firing['window']['end'], recovered['window']['end'],
                        'the condition watermark has to move forward')
        for event in (firing, recovered):
            validate_event(event, NOW + timedelta(seconds=120))
        # The repeat that *must* fold: the same verdict at the same instant is the pending replay.
        self.assertEqual(canonical(firing),
                         canonical(events.coverage_event(events.PARSE_COVERAGE_RULE,
                                                         firing=True, now=NOW)))

    def test_the_intake_bridge_carries_no_sample_and_a_visible_link_status(self):
        items = events.prepared(events.events_for(self.outcome.alert))
        self.assertEqual(len(items), 1)
        self.assertIsInstance(items[0], Prepared)
        self.assertIsNone(items[0].sample)
        self.assertEqual(items[0].link, 'not_configured')

    def test_a_batch_refuses_an_invented_sample_and_an_empty_event_list(self):
        built = events.events_for(self.outcome.alert)
        events.Batch(observed_at=NOW.isoformat(), events=built)
        with self.assertRaises(StateError):
            events.Batch(observed_at=NOW.isoformat(), events=built, samples=({'sample_id': 'x'},))
        with self.assertRaises(StateError):
            events.Batch(observed_at=NOW.isoformat(), events=())

    def test_validate_names_a_batch_the_state_layer_would_refuse(self):
        broken = [dict(event, window={'start': 'nope', 'end': 'nope'})
                  for event in events.events_for(self.outcome.alert)]
        with self.assertRaises(StateError):
            events.validate(events.Batch(observed_at=NOW.isoformat(), events=tuple(broken)), NOW)


# ------------------------------------------------------------------------- the collector


class FakeSource(collector.MailSource):
    def __init__(self, messages, generation='gen-1', fail=None):
        self.messages = dict(messages)
        self.generation = generation
        self.fail = fail or {}
        self.listed = []
        self.fetched = []

    def list_uids(self, *, after, limit):
        self.listed.append((after, limit))
        if 'list' in self.fail:
            raise self.fail['list']
        uids = sorted(uid for uid in self.messages if after is None or uid > after)
        return tuple(uids[:limit])

    def fetch(self, uid):
        self.fetched.append(uid)
        if 'fetch' in self.fail and uid in self.fail['fetch']:
            raise self.fail['fetch'][uid]
        return self.messages[uid]

    def mailbox_generation(self):
        if 'generation' in self.fail:
            raise self.fail['generation']
        return self.generation


class FakeSink(collector.EventSink):
    def __init__(self, fail_times=0):
        self.fail_times = fail_times
        self.admitted = []

    def admit(self, batch):
        if self.fail_times:
            self.fail_times -= 1
            raise RuntimeError('sink refuses: transient backend error')
        self.admitted.append(batch)


def config(root, **overrides):
    settings = {'schema_version': 1, 'source': 'identity-mail',
                'cursor_path': str(Path(root) / 'cursor' / 'identity-mail.json'),
                'interval_seconds': 60, 'max_messages': 4, 'max_message_bytes': 65536,
                'max_tick_bytes': 262144, 'coverage_window_seconds': 300,
                'max_silence_seconds': 3600, 'finding_window_seconds': 600,
                'policy': POLICY_DOCUMENT}
    settings.update(overrides)
    return settings


def message(uid, **kwargs):
    raw = alert(message_id=f'<alert-{uid}@accounts.example>', **kwargs)
    return uid, collector.FetchedMessage(uid=uid, raw=raw, attestation=attestation(raw))


def batched(items):
    return dict(items)


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        (self.root / 'cursor').mkdir()
        self.addCleanup(self._temp.cleanup)

    def state(self, settings):
        return collector.load_state(settings)

    def test_happy_path_files_findings_and_resolved_coverage(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1), message(2)])
        sink = FakeSink()
        report = collector.collect(settings, source, sink, now=NOW)
        self.assertEqual(report.status, 'delivered')
        self.assertEqual((report.fetched, report.findings), (2, 2))
        self.assertEqual(report.coverage, ())
        self.assertEqual(len(sink.admitted), 1)
        kinds = [event['kind'] for event in sink.admitted[0].events]
        self.assertEqual(kinds.count('security'), 2)
        filed = sorted({event['rule_id'] for event in sink.admitted[0].events
                        if event['kind'] == 'coverage'})
        self.assertEqual(filed, sorted(events.COVERAGE_RULES))
        state = self.state(settings)
        self.assertEqual(state['last_uid'], 2)
        self.assertIsNone(state['pending'])
        self.assertEqual(state['window']['findings'], 2)

    def test_sink_failure_keeps_the_batch_and_the_cursor_then_replays_before_reading(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1), message(2), message(3)])
        failing = FakeSink(fail_times=1)
        report = collector.collect(settings, source, failing, now=NOW)
        self.assertEqual(report.status, 'sink-failed')
        self.assertEqual(report.findings, 3)
        state = self.state(settings)
        self.assertIsNotNone(state['pending'])
        self.assertIsNone(state['last_uid']),
        self.assertEqual(state['pending']['through_uid'], 3)
        self.assertEqual(state['window']['findings'], 0, 'no counters before one commit point')

        source_two = FakeSource([message(1), message(2), message(3)])
        sink = FakeSink()
        replayed = collector.collect(settings, source_two, sink, now=NOW + timedelta(seconds=90))
        self.assertEqual(replayed.status, 'replayed')
        self.assertEqual(source_two.fetched, [], 'the replay must not re-read the mailbox')
        self.assertEqual(len(sink.admitted[0].events), 3 + 3)
        state = self.state(settings)
        self.assertEqual(state['last_uid'], 3)
        self.assertEqual(state['window']['findings'], 3)
        # Source-observation semantics, the identity mail collector replay repair: the cursor records when the mailbox
        # was
        # read (NOW), not when the retry landed. A replay reads nothing, so it cannot claim a fresher
        # read than the one it covers — that is what makes a sink that stays broken age into `stale`
        # instead of looking healthy forever. The old expectation (the replay instant) conflated the two.
        self.assertEqual(state['last_success_at'], utc_text(NOW))

    # ------------------------------------------------- the pending batch is a commit intent
    #
    # A pending entry is only safe to replay if it says everything the failed tick would have committed:
    # how far the read got, which mailbox instance it read, and whether that read completed. These pin
    # each of the five behaviours, then the refusals for a record that lies about one of them.

    def tamper(self, settings, mutate, *, repin=True):
        """Edit the stored cursor and write it back canonically, re-pinning the pending intent by default.

        Re-pinning is the point of most of these: with a valid fingerprint, only the consistency rules
        can catch the edit, which is what "reject malformed or inconsistent pending state" has to mean.
        """
        cursor = Path(settings['cursor_path'])
        document = json.loads(cursor.read_text())
        mutate(document)
        pending = document.get('pending')
        if repin and isinstance(pending, dict):
            pending['fingerprint'] = digest({name: value for name, value in pending.items()
                                             if name != 'fingerprint'})
        cursor.write_text(canonical(document))
        return document

    def test_replay_after_the_first_sink_failure_carries_the_generation_it_read(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(fail_times=1),
                          now=NOW)
        self.assertIsNone(self.state(settings)['generation_digest'],
                          'a batch not yet delivered has not adopted its generation')
        replayed = collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                                     now=NOW + timedelta(minutes=2))
        self.assertEqual(replayed.status, 'replayed')
        self.assertEqual(self.state(settings)['generation_digest'], digest(['gen-A']),
                         'the replay commits the generation the failed tick observed')
        source = FakeSource([message(1)], generation='gen-B')
        report = collector.collect(settings, source, FakeSink(), now=NOW + timedelta(minutes=4))
        self.assertTrue(report.mailbox_reset, 'a changed generation is still seen as a change')
        self.assertEqual(source.fetched, [1], 'and the new generation is read from UID 1')

    def test_coverage_only_pending_batch_at_the_cursor_replays(self):
        # A tick that read nothing new still files coverage, and its `through_uid` equals the cursor it
        # started from. That batch is not "behind" anything: refusing it on equality stops the feed.
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(fail_times=1),
                          now=NOW + timedelta(minutes=2))
        self.assertEqual(self.state(settings)['pending']['through_uid'], 3)
        report = collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                                   now=NOW + timedelta(minutes=4))
        self.assertEqual(report.status, 'replayed')
        self.assertEqual(self.state(settings)['last_uid'], 3, 'a coverage replay does not move the cursor')

    def test_pending_batch_after_a_generation_change_may_carry_a_lower_uid(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        collector.collect(settings, FakeSource([message(1)], generation='gen-B'),
                          FakeSink(fail_times=1), now=NOW + timedelta(minutes=2))
        self.assertEqual(self.state(settings)['last_uid'], 3,
                         'an undelivered restart does not move the cursor')
        report = collector.collect(settings, FakeSource([], generation='gen-B'), FakeSink(),
                                   now=NOW + timedelta(minutes=4))
        self.assertEqual(report.status, 'replayed')
        state = self.state(settings)
        self.assertEqual(state['last_uid'], 1, 'the restart lands where the new generation was read to')
        self.assertEqual(state['generation_digest'], digest(['gen-B']))

    def test_empty_new_generation_clears_the_cursor_so_its_uid_one_is_read(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        first = collector.collect(settings, FakeSource([], generation='gen-B'), FakeSink(),
                                 now=NOW + timedelta(minutes=2))
        self.assertTrue(first.mailbox_reset)
        state = self.state(settings)
        self.assertIsNone(state['last_uid'],
                          'a restart with nothing read yet holds no position from the old mailbox')
        self.assertEqual(state['generation_digest'], digest(['gen-B']))
        source = FakeSource([message(1)], generation='gen-B')
        collector.collect(settings, source, FakeSink(), now=NOW + timedelta(minutes=4))
        self.assertEqual(source.fetched, [1], 'the old UID 3 must not skip the new UID 1')

    def test_failed_read_then_sink_failure_replays_without_a_source_success(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        broken = FakeSource([], generation='gen-A', fail={'list': RuntimeError('fixture read failure')})
        collector.collect(settings, broken, FakeSink(fail_times=1), now=NOW + timedelta(minutes=2))
        pending = self.state(settings)['pending']
        self.assertIs(pending['source_read'], False, 'the batch knows its own read never completed')
        self.assertEqual(pending['through_uid'], 3)
        replayed = collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                                     now=NOW + timedelta(minutes=4))
        self.assertEqual(replayed.reasons, ('pending-batch', 'source-read-failed'),
                         'and the replay says so')
        state = self.state(settings)
        self.assertEqual(state['last_success_at'], utc_text(NOW),
                         'a replay of a failed read is not a source success')
        self.assertEqual(state['last_uid'], 3)
        later = collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                                  now=NOW + timedelta(minutes=6))
        self.assertEqual(later.silence_seconds, 360, 'the silence clock runs from the last real read')

    def test_failed_listing_during_reset_cannot_commit_the_reset_on_replay(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        broken = FakeSource([], generation='gen-B', fail={'list': RuntimeError('fixture read failure')})
        collector.collect(settings, broken, FakeSink(fail_times=1), now=NOW + timedelta(minutes=2))
        collector.collect(settings, FakeSource([], generation='gen-B'), FakeSink(),
                          now=NOW + timedelta(minutes=4))
        state = self.state(settings)
        self.assertEqual(state['last_uid'], 3)
        self.assertEqual(state['generation_digest'], digest(['gen-A']))
        self.assertEqual(state['last_success_at'], utc_text(NOW))

    def test_a_pending_record_without_its_source_facts_is_refused_not_migrated(self):
        # The pre-binding pending shape cannot say whether its read completed, so it is unsupported:
        # schema_version stays 1, nothing migrates it, nothing silently drops the batch or the cursor.
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)], generation='gen-A'),
                          FakeSink(fail_times=1), now=NOW)

        def strip(document):
            for name in ('generation_digest', 'source_read'):
                del document['pending'][name]

        self.tamper(settings, strip, repin=False)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                              now=NOW + timedelta(minutes=2))
        self.assertEqual(set(json.loads(Path(settings['cursor_path']).read_text())['pending']),
                         {'batch', 'fingerprint', 'through_uid', 'tally'},
                         'the refused record stays on disk for inspection, unmodified')

    def test_a_pending_batch_behind_the_cursor_without_a_generation_change_is_refused(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        collector.collect(settings, FakeSource([message(5)], generation='gen-A'),
                          FakeSink(fail_times=1), now=NOW + timedelta(minutes=2))

        def rewind(document):
            document['pending']['through_uid'] = 2

        self.tamper(settings, rewind)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                              now=NOW + timedelta(minutes=4))

    def test_a_pending_batch_that_moves_the_cursor_without_a_completed_read_is_refused(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(3)], generation='gen-A'), FakeSink(), now=NOW)
        broken = FakeSource([], generation='gen-A', fail={'list': RuntimeError('fixture read failure')})
        collector.collect(settings, broken, FakeSink(fail_times=1), now=NOW + timedelta(minutes=2))

        def invent(document):
            document['pending']['through_uid'] = 9

        self.tamper(settings, invent)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                              now=NOW + timedelta(minutes=4))

    def test_inconsistent_or_untyped_pending_source_facts_are_refused(self):
        for name, value in (('source_read', 'true'), ('source_read', None),
                            ('generation_digest', 'gen-B'), ('generation_digest', 7)):
            with self.subTest(field=name, value=value):
                settings = collector.settings(config(self.root))
                Path(settings['cursor_path']).unlink(missing_ok=True)
                collector.collect(settings, FakeSource([message(1)], generation='gen-A'),
                                  FakeSink(fail_times=1), now=NOW)
                self.tamper(settings, lambda document, item=(name, value):
                            document['pending'].__setitem__(*item))
                with self.assertRaises(collector.CollectorError):
                    collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                                      now=NOW + timedelta(minutes=2))

    def test_an_edited_pending_generation_is_caught_by_the_fingerprint(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)], generation='gen-A'),
                          FakeSink(fail_times=1), now=NOW)

        def forge(document):
            document['pending']['generation_digest'] = digest(['gen-B'])

        self.tamper(settings, forge, repin=False)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([], generation='gen-B'), FakeSink(),
                              now=NOW + timedelta(minutes=2))

    def test_a_pending_batch_observed_after_the_clock_is_refused(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)], generation='gen-A'),
                          FakeSink(fail_times=1), now=NOW)

        def push(document):
            document['pending']['batch']['observed_at'] = utc_text(NOW + timedelta(hours=1))

        self.tamper(settings, push)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([], generation='gen-A'), FakeSink(),
                              now=NOW + timedelta(minutes=2))

    def test_a_corrupt_pending_fingerprint_is_refused_rather_than_delivered(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)]), FakeSink(fail_times=1), now=NOW)
        path = Path(settings['cursor_path'])
        state = json.loads(path.read_text())
        state['pending']['batch']['events'] = state['pending']['batch']['events'][:1]
        path.write_text(canonical(state))
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([]), FakeSink(), now=NOW + timedelta(minutes=2))

    def test_reads_stop_at_the_message_budget_and_say_so(self):
        settings = collector.settings(config(self.root, max_messages=2))
        source = FakeSource([message(uid) for uid in range(1, 6)])
        sink = FakeSink()
        report = collector.collect(settings, source, sink, now=NOW)
        self.assertEqual(report.fetched, 2)
        self.assertTrue(report.truncated is False, 'a full page is not a mid-queue stop')
        self.assertIn(events.SOURCE_COVERAGE_RULE, report.coverage)
        self.assertEqual(self.state(settings)['last_uid'], 2)
        self.assertTrue(report.backlog, 'a full page says more may be waiting')
        self.assertFalse(report.truncated, 'nothing was stopped mid-queue')
        second = collector.collect(settings, source, sink, now=NOW + timedelta(minutes=2))
        self.assertEqual(second.fetched, 2)
        self.assertEqual(self.state(settings)['last_uid'], 4)
        third = collector.collect(settings, source, sink, now=NOW + timedelta(minutes=4))
        self.assertEqual((third.fetched, third.backlog), (1, False), 'the queue drained')
        self.assertEqual(self.state(settings)['last_uid'], 5)

    def test_an_oversized_message_is_counted_and_never_truncated_into_a_verdict(self):
        settings = collector.settings(config(self.root, max_message_bytes=4096))
        small = alert(message_id='<small@accounts.example>')
        big = alert(message_id='<big@accounts.example>', body='x' * 5000)
        source = FakeSource({1: collector.FetchedMessage(uid=1, raw=big,
                                                        attestation=attestation(big)),
                             2: collector.FetchedMessage(uid=2, raw=small,
                                                         attestation=attestation(small))})
        sink = FakeSink()
        report = collector.collect(settings, source, sink, now=NOW)
        self.assertEqual(report.parse_failures, 1)
        self.assertIn('oversized-message', report.reasons)
        self.assertEqual(report.findings, 1, 'the readable alert is still filed')
        self.assertEqual(self.state(settings)['last_uid'], 2)
        self.assertEqual(len(sink.admitted[0].events), 1 + 3)

    def test_reads_stop_at_the_tick_byte_budget_and_leave_the_rest_unread(self):
        # Each message is ~1.5 KiB and the tick budget is 4 KiB, so three are read, the budget is gone,
        # and the fourth is never fetched. The cursor stops at what was actually handled.
        settings = collector.settings(config(self.root, max_tick_bytes=4096, max_message_bytes=4096,
                                             max_messages=4))
        blobs = {uid: alert(message_id=f'<pad-{uid}@accounts.example>', body='y' * 1200)
                 for uid in range(1, 6)}
        source = FakeSource({uid: collector.FetchedMessage(uid=uid, raw=blob,
                                                         attestation=attestation(blob))
                             for uid, blob in blobs.items()})
        sink = FakeSink()
        report = collector.collect(settings, source, sink, now=NOW)
        self.assertEqual(report.fetched, 3)
        self.assertEqual(report.bytes_read, sum(len(blobs[uid]) for uid in (1, 2, 3)))
        self.assertTrue(report.truncated)
        self.assertIn('read-budget-exhausted', report.reasons)
        self.assertEqual(self.state(settings)['last_uid'], 3)
        self.assertEqual(source.fetched, [1, 2, 3], 'the budget stop is a stop, not a partial read')
        for event in sink.admitted[0].events:
            if event['kind'] == 'coverage':
                self.assertIn(events.SOURCE_COVERAGE_RULE, events.COVERAGE_RULES)
        self.assertIn(events.SOURCE_COVERAGE_RULE, report.coverage)

    def test_unfetchable_message_is_counted_and_the_cursor_stays_behind_it(self):
        settings = collector.settings(config(self.root))
        good = alert(message_id='<b@accounts.example>')
        source = FakeSource({1: collector.FetchedMessage(uid=1, raw=good, attestation=attestation(good)),
                             2: collector.FetchedMessage(uid=2, raw=good, attestation=None)},
                            fail={'fetch': {2: TimeoutError('read timed out')}})
        report = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual(report.parse_failures, 1)
        self.assertEqual(self.state(settings)['last_uid'], 1)
        self.assertIn('TimeoutError', report.reasons)
        self.assertEqual(report.status, 'delivered')

    def test_transport_failure_files_firing_coverage_and_does_not_fake_a_read(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1)], fail={'list': OSError('mailbox unavailable')})
        sink = FakeSink()
        report = collector.collect(settings, source, sink, now=NOW)
        self.assertEqual(report.status, 'transport-failed')
        self.assertEqual(report.fetched, 0)
        self.assertEqual(report.coverage, (events.SOURCE_COVERAGE_RULE,))
        state = self.state(settings)
        self.assertIsNone(state['last_success_at'], 'a tick that read nothing completed nothing')
        again = collector.collect(settings, source, sink, now=NOW + timedelta(seconds=1))
        self.assertEqual(again.status, 'transport-failed', 'no interval claim on a failed read')

    def test_silence_past_the_limit_opens_source_coverage(self):
        settings = collector.settings(config(self.root, max_silence_seconds=120))
        source = FakeSource([])
        first = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual(first.coverage, ())
        later = collector.collect(settings, source, FakeSink(), now=NOW + timedelta(minutes=10))
        self.assertEqual(later.coverage, (events.SOURCE_COVERAGE_RULE,))
        self.assertGreaterEqual(later.silence_seconds, 600)
        self.assertTrue(later.stale)

    def test_mailbox_generation_change_restarts_the_cursor_and_fires_coverage(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1)], generation='gen-1')
        collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual(self.state(settings)['last_uid'], 1)
        second = FakeSource([message(1), message(2)], generation='gen-2')
        report = collector.collect(settings, second, FakeSink(), now=NOW + timedelta(minutes=2))
        self.assertTrue(report.mailbox_reset)
        self.assertIn(events.SOURCE_COVERAGE_RULE, report.coverage)
        self.assertEqual(report.fetched, 2, 'the new generation is read from the start')

    def test_out_of_order_identifiers_are_dropped_and_flagged(self):
        settings = collector.settings(config(self.root))

        class Disorderly(FakeSource):
            def list_uids(self, *, after, limit):
                return (2, 1, 3)

        source = Disorderly([message(1), message(2), message(3)])
        report = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertTrue(report.uid_regression)
        self.assertIn(events.SOURCE_COVERAGE_RULE, report.coverage)
        self.assertEqual(source.fetched, [2, 3])
        self.assertEqual(self.state(settings)['last_uid'], 3)

    def test_idle_tick_reads_nothing(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1)])
        collector.collect(settings, source, FakeSink(), now=NOW)
        before = len(source.listed)
        report = collector.collect(settings, source, FakeSink(), now=NOW + timedelta(seconds=10))
        self.assertEqual(report.status, 'idle')
        self.assertEqual(len(source.listed), before)

    def test_overlapping_schedule_exits_idle_instead_of_the_lock(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1)])
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        with mock.patch('local_observe.identity_mail.collector.exclusive_owner',
                        side_effect=BlockingIOError('locked by another worker')):
            report = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual(report.status, 'idle')
        self.assertEqual(report.reasons, ('owner-lock-held',))
        self.assertEqual(source.listed, [])

    def test_untrusted_and_parse_failures_are_separate_monitorable_counts(self):
        settings = collector.settings(config(self.root))
        forged = alert(message_id='<forged@accounts.example>',
                       extra='Authentication-Results: 1; dkim=pass header.d=accounts.example\r\n',
                       auth='1; spf=none')
        broken = b'From: no-reply@accounts.example\r\nthis line has no colon\r\n\r\nbody'
        source = FakeSource({1: collector.FetchedMessage(uid=1, raw=forged, attestation=None),
                             2: collector.FetchedMessage(uid=2, raw=broken, attestation=None),
                             4: message(4)[1]})
        report = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual((report.untrusted, report.parse_failures, report.findings), (1, 1, 1))
        self.assertEqual(report.parse_failure_ratio, round(1 / 3, 4))
        self.assertEqual(sorted(report.coverage), [events.PARSE_COVERAGE_RULE,
                                                   events.UNTRUSTED_COVERAGE_RULE])
        self.assertEqual(report.bytes_read, len(forged) + len(broken) + len(alert(message_id='<alert-4@'
                                                                                  'accounts.example>')))

    def test_settings_and_cursor_refusals(self):
        base = config(self.root)
        for name, value in (('schema_version', 2), ('source', 'other-mail'), ('interval_seconds', 1),
                            ('max_messages', 99), ('max_tick_bytes', 1024),
                            ('cursor_path', 'relative/path.json'), ('coverage_window_seconds', 0),
                            ('max_silence_seconds', 10), ('finding_window_seconds', 30)):
            with self.subTest(field=name):
                with self.assertRaises(collector.CollectorError):
                    collector.settings(dict(base, **{name: value}))
        with self.assertRaises(collector.CollectorError):
            collector.settings(dict(base, unexpected=1))
        with self.assertRaises(collector.CollectorError):
            collector.settings(dict(base, policy={'schema_version': 1}))
        self.assertEqual(collector.settings(base)['policy_fingerprint'],
                         collector.settings(collector.settings(base))['policy_fingerprint'])

    def test_a_cursor_from_another_configuration_is_refused(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)]), FakeSink(), now=NOW)
        with self.assertRaises(collector.CollectorError):
            collector.collect(collector.settings(config(self.root, interval_seconds=300)),
                              FakeSource([message(2)]), FakeSink(), now=NOW + timedelta(minutes=9))

    def test_a_symlinked_cursor_and_a_non_canonical_file_are_refused(self):
        settings = collector.settings(config(self.root))
        cursor = Path(settings['cursor_path'])
        other = self.root / 'other.json'
        other.write_text('{}')
        cursor.symlink_to(other)
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([]), FakeSink(), now=NOW)
        cursor.unlink()
        collector.collect(settings, FakeSource([message(1)]), FakeSink(), now=NOW)
        cursor.write_text(json.dumps(json.loads(cursor.read_text()), indent=1))
        with self.assertRaises(collector.CollectorError):
            collector.collect(settings, FakeSource([]), FakeSink(), now=NOW + timedelta(minutes=2))

    def test_batch_round_trips_through_the_cursor_byte_for_byte(self):
        settings = collector.settings(config(self.root))
        collector.collect(settings, FakeSource([message(1)]), FakeSink(fail_times=1), now=NOW)
        state = json.loads(Path(settings['cursor_path']).read_text())
        rebuilt = collector._batch(state['pending']['batch'])
        self.assertEqual(canonical(collector.batch_json(rebuilt)), canonical(state['pending']['batch']))
        with self.assertRaises(collector.CollectorError):
            collector._batch({'observed_at': NOW.isoformat(), 'events': [], 'samples': []})
        with self.assertRaises(collector.CollectorError):
            collector._batch({'observed_at': NOW.isoformat(), 'events': [{'source': 'other'}],
                              'samples': []})

    def test_seams_are_abstract_so_no_implicit_default_exists(self):
        with self.assertRaises(NotImplementedError):
            collector.MailSource().list_uids(after=None, limit=1)
        with self.assertRaises(NotImplementedError):
            collector.MailSource().fetch(1)
        with self.assertRaises(NotImplementedError):
            collector.MailSource().mailbox_generation()
        with self.assertRaises(NotImplementedError):
            collector.EventSink().admit(events.Batch(observed_at=NOW.isoformat(),
                                                    events=events.events_for(
                                                        parse(alert(), attestation(alert()))
                                                        .alert)))

    def test_no_network_path_is_reached(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1), message(2)], fail={})
        with mock.patch('socket.socket', side_effect=AssertionError('a socket was opened')), \
                mock.patch('socket.create_connection', side_effect=AssertionError('a socket was opened')):
            report = collector.collect(settings, source, FakeSink(), now=NOW)
        self.assertEqual(report.findings, 2)

    def test_provider_text_never_enters_the_cursor(self):
        settings = collector.settings(config(self.root))
        source = FakeSource([message(1)], generation='uidvalidity-7788')
        collector.collect(settings, source, FakeSink(), now=NOW)
        text = Path(settings['cursor_path']).read_text()
        self.assertNotIn('uidvalidity', text)
        self.assertNotIn('@', text)
        self.assertNotIn('MARKER', text)


if __name__ == '__main__':
    unittest.main()
