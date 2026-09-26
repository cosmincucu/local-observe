"""Self-test for `lo-platform notify`: what the CLI does when nobody says which mode to send in.

Ledger test tooling item 2. `NotificationPolicy.delivery_mode` used to default to `live`, so the one product
entry point that built a policy itself — this CLI's `notify` subcommand, which opened the store with
no policy at all — attempted a real human-channel delivery on every run. The API had already moved to
`recording` (api errors); the CLI had not. These tests pin what the fix has to keep: the default records,
`live` is reachable only through `--mode` or `LO_NOTIFICATION_MODE`, and a mode that is neither of the
three is refused rather than quietly resolved to whichever looks safe.

Everything runs in-process against a real `Store` on a temp path, with the network client substituted
(`cli.JsonClient`) so an accepted send is evidence of a route and never of a message that left the
machine. The CLI reads `sys.argv`, so each call swaps it for the duration of one run.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from local_observe.inventory.validation import utc_text
from local_observe.platform import cli
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, Store


@contextlib.contextmanager
def notification_environment(mode: str | None):
    """Run the block with `LO_NOTIFICATION_MODE` set to `mode`, or genuinely absent when it is None.

    The empty string is a different case from unset and is tested separately: since notification and state leftovers a
    variable
    that is present and blank is a refusal naming it, because the line was written and said nothing.
    """
    key = cli.MODE_ENVIRONMENT
    previous = os.environ.get(key)
    if mode is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = mode
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous


class FakeChannel:
    """Stand-in for `cli.JsonClient`: records the send, acknowledges it, never touches a socket."""

    instances: list[FakeChannel] = []

    def __init__(self, url: str, token: str) -> None:
        """Capture the construction arguments as evidence that the live route was opened, or not."""
        self.url = url
        self.token = token
        self.sent: list[dict] = []
        FakeChannel.instances.append(self)

    def request(self, method: str, *, payload: dict, headers: dict) -> tuple[int, dict]:
        """Acknowledge one delivery the way the real channel does, so the outbox advances."""
        self.sent.append(payload)
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


class NotifyModeTests(unittest.TestCase):
    """Every route `lo-platform notify` can take, and the ones it must refuse to take."""

    def setUp(self) -> None:
        """Open a scratch database with no rows, a credential file, and a clean environment."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / 'platform.db'
        self.token = self.root / 'channel-token'
        self.token.write_text('a-token-value-not-to-be-read\n', encoding='utf-8')
        self.token.chmod(0o600)
        FakeChannel.instances = []
        os.environ.pop(cli.MODE_ENVIRONMENT, None)
        self.addCleanup(os.environ.pop, cli.MODE_ENVIRONMENT, None)

    def queue(self) -> dt.datetime:
        """Create the database and enqueue one delivery from a real, non-synthetic detector.

        The event is stamped with the current time, not a fixture instant: the CLI cannot be handed a
        `now`, so the delivery it makes is judged against the real clock and would otherwise age out.

        Each call gets its own resource, and so its own condition domain: two events on one domain
        carry the second one into the incident the first opened, which queues no delivery at all. A
        test that needs a second pending row must therefore not share a resource with the first.
        """
        now = dt.datetime.now(dt.timezone.utc)
        store = Store(self.database)
        window = {'start': utc_text(now - dt.timedelta(seconds=60)), 'end': utc_text(now)}
        item = event('notify-test', str(uuid.uuid4()), 'notify-rule', 'availability', 'firing', window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        store.intake(item, Actor('notify-test', 'producer'), now=now)
        return now

    def run_cli(self, *argv: str) -> tuple[int, dict, str]:
        """Run `lo-platform` in-process over `argv`; return its exit status, its JSON and its log."""
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.database), *argv]
        printed, logged = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        return code, json.loads(printed.getvalue()), logged.getvalue()

    def rows(self, query: str) -> list[tuple]:
        """Run one read-only query against the database the CLI just wrote."""
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            return [tuple(row) for row in connection.execute(query)]

    def recorded_mode(self) -> str | None:
        """Return the delivery mode the database says it is under, or None while nothing recorded one.

        `notification_control.mode` is the row `Store.start_notification_mode` writes and the row the
        live-over-a-paused-backlog gate reads, so this is the durable answer to "did that run pass
        through the gate, or around it?"
        """
        rows = self.rows("SELECT value FROM notification_control WHERE key='mode'")
        return rows[0][0] if rows else None

    def recording_install(self) -> None:
        """Build the state a recording install leaves behind: its mode recorded, one delivery paused.

        This is the exact shape the live-activation gate exists for — the operator ran the platform
        under `recording`, a backlog accumulated, and `--mode live` now points at the same file.
        """
        self.queue()
        Store(self.database).start_notification_mode()
        self.assertEqual('recording', self.recorded_mode())

    def route(self) -> list[tuple[str, str]]:
        """Return the (channel, destination) of every send slot the database says was taken."""
        return self.rows('SELECT channel, destination FROM notification_reservations')

    def outbox(self) -> list[str]:
        """Return the outbox statuses on disk, so a refused run can be shown to have taken nothing."""
        return [row[0] for row in self.rows('SELECT status FROM outbox ORDER BY sequence')]

    def test_no_flag_and_no_environment_records_instead_of_sending(self) -> None:
        """The ledger's verification line: the slot is taken against the recording sink, not a human."""
        self.queue()
        with notification_environment(None), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify')

        self.assertEqual(0, code)
        self.assertEqual('sent', result['status'])
        self.assertEqual('recording-sink', result['destination'])
        self.assertEqual([('primary', 'recording-sink')], self.route())
        self.assertEqual(['sent'], self.outbox())
        self.assertEqual([], FakeChannel.instances, 'no network client was ever constructed')
        audit = self.rows("SELECT operation, json_extract(detail,'$.destination') FROM audit "
                          "WHERE operation LIKE 'notification.%'")
        self.assertIn(('notification.reserved', 'recording-sink'), audit,
                      f'the reserved slot must name the recording sink, audit was {audit}')
        self.assertNotIn('human', [destination for _, destination in audit],
                         'no audit row on the default path may name the human channel')

    def test_a_bare_policy_names_recording(self) -> None:
        """The default the CLI stopped needing: a policy built with no arguments is not a sender."""
        self.assertEqual('recording', NotificationPolicy().delivery_mode)
        self.assertEqual('recording', NotificationPolicy().delivery_mode)

    def test_environment_alone_selects_recording(self) -> None:
        """`LO_NOTIFICATION_MODE` is read by the CLI as it is by the API, with no flag involved."""
        self.queue()
        with notification_environment('recording'), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify')
        self.assertEqual(0, code)
        self.assertEqual('recording-sink', result['destination'])
        self.assertEqual([], FakeChannel.instances)

    def test_off_from_the_environment_sends_nothing_at_all(self) -> None:
        """`off` pauses the sender: the delivery is suppressed with a reason and no slot is taken."""
        self.queue()
        with notification_environment('off'):
            code, result, _ = self.run_cli('notify')
        self.assertEqual(0, code)
        self.assertEqual('suppressed', result['status'])
        self.assertEqual('notifications-disabled', result['reason'])
        self.assertEqual([], self.route())

    def test_the_flag_overrides_the_environment(self) -> None:
        """A flag on the command line is the operator speaking directly, so it wins over the variable."""
        self.queue()
        with notification_environment('off'), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--mode', 'recording')
        self.assertEqual(0, code)
        self.assertEqual('recording-sink', result['destination'])
        self.assertEqual([('primary', 'recording-sink')], self.route())

    def test_live_needs_naming_and_reaches_the_human_channel_when_it_does(self) -> None:
        """`live` still works, and only on its own terms: the flag, a url and a token file."""
        self.queue()
        with notification_environment(None), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--mode', 'live', '--url', 'https://channel.invalid',
                                           '--token-file', str(self.token))
        self.assertEqual(0, code)
        self.assertEqual('human', result['destination'])
        self.assertEqual([('primary', 'human')], self.route())
        self.assertEqual(1, len(FakeChannel.instances))
        self.assertEqual('https://channel.invalid', FakeChannel.instances[0].url)
        self.assertEqual('a-token-value-not-to-be-read', FakeChannel.instances[0].token)

    def test_the_environment_naming_live_is_explicit_enough(self) -> None:
        """The variable is a declaration too; the CLI does not demand the flag on top of it."""
        self.queue()
        with notification_environment('live'), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--url', 'https://channel.invalid',
                                           '--token-file', str(self.token))
        self.assertEqual(0, code)
        self.assertEqual('human', result['destination'])
        self.assertEqual(1, len(FakeChannel.instances))

    def test_live_without_a_channel_is_refused_and_leaves_the_queue_alone(self) -> None:
        """Asking for live with nowhere to send must not consume the delivery it cannot make."""
        self.queue()
        with notification_environment(None):
            code, result, _ = self.run_cli('notify', '--mode', 'live')
        self.assertEqual(1, code)
        self.assertEqual('error', result['status'])
        self.assertEqual('ValueError', result['error_type'])
        self.assertEqual(['pending'], self.outbox())
        self.assertEqual([], self.route())
        self.assertEqual([], FakeChannel.instances)
        # The channel is built before any state is written, so a run that never had a route to send
        # on also never rewrote the mode this database is recorded as running under.
        self.assertIsNone(self.recorded_mode(), 'a refused live run must not record live')

    def test_an_unrecognised_mode_is_a_refusal_not_a_fallback(self) -> None:
        """A half-typed mode must not land on any mode at all, and least of all on the live one.

        The blank entries are notification and state leftovers: a variable set to nothing was still written by
        someone, and both
        entry points refuse it rather than answering with the default.
        """
        self.queue()
        for mode in ('Live', 'LIVE', 'record', 'sen d', '0', 'true', '', '   '):
            with self.subTest(mode=mode), notification_environment(mode):
                code, result, _ = self.run_cli('notify')
            self.assertEqual(1, code)
            self.assertEqual('error', result['status'])
        self.assertEqual(['pending'], self.outbox())
        self.assertEqual([], self.route())

    def test_recording_never_reads_the_channel_credential(self) -> None:
        """The credential file stays closed unless the mode is live: a missing file proves it here."""
        self.queue()
        missing = self.root / 'token-that-does-not-exist'
        with mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--url', 'https://channel.invalid',
                                           '--token-file', str(missing))
        self.assertEqual(0, code)
        self.assertEqual('recording-sink', result['destination'])
        self.assertEqual([], FakeChannel.instances)

    def test_mode_resolution_prefers_flag_then_environment_then_recording(self) -> None:
        """The precedence rule as a unit, with no database and no subprocess in the way."""
        with notification_environment(None):
            self.assertEqual('recording', cli.notification_mode(None))
            self.assertEqual('off', cli.notification_mode('off'))
            self.assertEqual('live', cli.notification_mode('live'))
        with notification_environment('off'):
            self.assertEqual('off', cli.notification_mode(None))
            self.assertEqual('live', cli.notification_mode('live'))
        with notification_environment(''):
            with self.assertRaisesRegex(ValueError, 'LO_NOTIFICATION_MODE'):  # blank is not unset
                cli.notification_mode(None)
        with notification_environment('   '):
            with self.assertRaisesRegex(ValueError, 'LO_NOTIFICATION_MODE'):
                cli.notification_mode(None)
        with notification_environment(' live '):
            self.assertEqual('live', cli.notification_mode(None))
        for value in ('LIVE', 'record', 'nope', '0', 'sen d'):
            with self.subTest(value=value), notification_environment(value):
                with self.assertRaises(ValueError):
                    cli.notification_mode(None)


    def test_live_over_a_paused_backlog_is_refused_and_changes_nothing(self) -> None:
        """The ledger's verification line for test tooling item 1: the CLI refuses where the API would refuse.

        `Store.start_notification_mode` is what writes `notification_control.mode` and what refuses a
        live startup over a backlog left paused under `off`/`recording`. The API's lifespan called it
        and this CLI did not, so `notify --mode live` against a recording database sent anyway.
        """
        self.recording_install()
        with notification_environment(None), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--mode', 'live', '--url', 'https://channel.invalid',
                                           '--token-file', str(self.token))
        self.assertEqual(1, code)
        self.assertEqual('error', result['status'])
        self.assertEqual('StateError', result['error_type'],
                         'the refusal is the same Store error the API lifespan raises')
        self.assertEqual('recording', self.recorded_mode(),
                         'a refused activation must not rewrite the recorded mode')
        self.assertEqual(['pending'], self.outbox(), 'the paused delivery stays paused')
        self.assertEqual([], self.route(), 'no send slot is taken by a run that never delivered')
        self.assertEqual([], FakeChannel.instances, 'no network client was ever constructed')

    def test_the_same_store_delivers_once_the_api_path_has_opened_it_live(self) -> None:
        """The other half of that gate: reconcile the backlog, activate as the lifespan does, it sends."""
        self.recording_install()
        # Reconciling a paused backlog is a recording run: nothing else drains an outbox that was
        # never allowed to send, and this is what the operator does before asking for live.
        with mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify')
        self.assertEqual((0, 'sent', 'recording-sink'), (code, result['status'], result['destination']))
        self.assertEqual([], FakeChannel.instances)
        # This one call is everything `platform.api`'s lifespan does with a live policy.
        Store(self.database, NotificationPolicy(delivery_mode='live')).start_notification_mode()
        self.assertEqual('live', self.recorded_mode())
        self.queue()
        with notification_environment(None), mock.patch.object(cli, 'JsonClient', FakeChannel):
            code, result, _ = self.run_cli('notify', '--mode', 'live', '--url', 'https://channel.invalid',
                                           '--token-file', str(self.token))
        self.assertEqual(0, code)
        self.assertEqual('human', result['destination'])
        # Membership and count, not position: a bare `SELECT channel, destination` over
        # `notification_reservations` is served by the covering index `reservations_window`, so it comes
        # back ordered by (channel, destination, at) and not by the order the slots were taken — a
        # human slot reads ahead of a recording-sink one no matter which was reserved first. Both must
        # simply be in the table, one of them human.
        self.assertIn(('primary', 'human'), self.route())
        self.assertEqual(1, sum(1 for _, destination in self.route() if destination == 'human'))
        self.assertEqual(1, len(FakeChannel.instances))


class ModuleContractTests(unittest.TestCase):
    """The three helpers are the whole policy of the subcommand, so their shape is pinned too."""

    def test_the_flag_offers_exactly_the_modes_the_policy_accepts(self) -> None:
        """Every mode the flag can name must be one NotificationPolicy will build, and vice versa."""
        self.assertEqual(('off', 'recording', 'live'), cli.NOTIFICATION_MODES)
        for mode in cli.NOTIFICATION_MODES:
            self.assertEqual(mode, NotificationPolicy(delivery_mode=mode).delivery_mode)
        self.assertEqual('recording', cli.DEFAULT_MODE)
        self.assertEqual('LO_NOTIFICATION_MODE', cli.MODE_ENVIRONMENT)

    def test_sender_builds_a_local_sink_for_every_non_live_mode(self) -> None:
        """No mode except live can produce a client that holds a URL."""
        args = mock.Mock(url='https://channel.invalid', token_file=None)
        for mode in ('off', 'recording'):
            self.assertIsInstance(cli.sender(args, mode), cli.RecordingSink)
        with self.assertRaises(ValueError):
            cli.sender(args, 'live')
        # The same live-channel refusal, reachable on its own: `main` has to make it before the
        # startup gate writes this database's mode, and `sender` is called only after that gate.
        cli.check_channel(args, 'recording')
        with self.assertRaises(ValueError):
            cli.check_channel(args, 'live')
