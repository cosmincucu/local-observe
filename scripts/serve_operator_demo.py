"""Local operator UI using isolated synthetic state; no production actions or delivery.

The demo serves the real platform app over a real SQLite file, so an operator surface can be driven in a
browser without touching a deployment. Two things are deliberately separated here:

* **the shared default fixture** (`scratch/operator-demo`) is *reused* between runs — that is what keeps a
  long-lived demo server and its credentials alive across checker invocations, and it is what the
  existing `check_operator_browser.py` reads;
* **an explicit `--fixture <directory>`** is a *fresh* fixture: it refuses a directory that already holds
  anything rather than reusing somebody's credentials or database, so a proof run can be handed a unique
  path and know every byte in it was written by this run.

A background launch honours that split too. The parent prepares the fresh fixture, opens its two log
files as **new siblings outside** that directory (never inside it — a log written into the fixture would
make the child refuse the directory it was just handed), and passes the child the resolved absolute path,
which the child checks the ordinary way. The shared default keeps appending its logs inside the fixture,
as it always did. There is no flag to "allow" an existing file in either direction: refusal is the design.

The seeded history is synthetic and bounded. It carries one open incident, one action still awaiting a
decision (the approval workflow), and two terminal executions — one with two saved verification records,
one with none — so the read-only verification history in the execution detail has something to read and
something to report as empty, without either being invented. Nothing here sends anything, notifies, or
grades a verdict: records are filed through `Store.put_verification`, the same call a real verifier's
submission reaches, and the server derives every verdict.

The insertion order below is load-bearing and not cosmetic: `Store.records()` answers `ORDER BY rowid
DESC`, so the *newest* row is the first one the UI lists. The pending approval and the availability event
must therefore be written last, or the existing operator browser checker — which inspects `.first` of the
approvals and events tables — would inspect different records than it was written against.
"""
import datetime as dt
import json
from pathlib import Path
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from local_observe.inventory.index import build
from local_observe.inventory.validation import read_document, utc_text
from local_observe.platform import detections
from local_observe.platform.api import create_app
from local_observe.platform.operator import with_ui
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Store, Actor
from local_observe.platform.verification_records import VerificationPolicy
from local_observe.store import client as facade
from local_observe.store.client import MetricSample, Window

#: The fixture this script has always used. Passing no `--fixture` keeps reusing it, credentials included.
DEFAULT_FIXTURE = ROOT / 'scratch' / 'operator-demo'
#: Names a fresh fixture instead. Never reused, never repaired: see :func:`fixture_directory`.
FIXTURE_OPTION = '--fixture'
BACKGROUND_OPTION = '--background'
#: The two files a background server's own output is written to, in the shared fixture's case inside it.
LOG_NAMES = ('server.stdout.log', 'server.stderr.log')

# The synthetic signal everything below is a statement about. Same source/rule/version/condition/resource
# as the availability event the demo has always fired, so the verification history belongs to the one
# incident the demo shows rather than opening a second one.
DETECTOR = 'demo-detector'
RULE = 'synthetic.availability'
RULE_VERSION = '1'
METRIC = 'lo_cpu'
#: An obviously synthetic reviewed artifact pin, in the shape the policy validator requires.
ARTIFACT = '0123456789abcdef' * 4
#: The one window length the demo's reviewed mapping evaluates, so a submitted window may be exactly this.
WINDOW_SECONDS = 300
# The threshold and comparison the demo's mapping reviews. The seeded reading sits above the line, which
# is what makes the saved verdict `not_cleared` on an execution whose runner reported `succeeded`.
THRESHOLD = 90.0
COMPARISON = 'lt'
STILL_FIRING = 95.0
VERIFIER = 'demo-verifier'
OPERATOR = 'demo-operator'
READER = 'demo-reader'
RUNNER = 'demo-runner'
PROPOSER = 'demo-proposer'
#: The still-unanswered approval the demo exists to demonstrate, and the two executions that already ran.
PENDING_RETRY_KEY = 'demo-action'
VERIFIED_RETRY_KEY = 'demo-verified-action'
UNVERIFIED_RETRY_KEY = 'demo-unverified-action'
#: Sentinel for "mount the demo's own reviewed policy"; `policy=None` must be able to mean the opposite.
MOUNT_DEMO_POLICY = object()


def options(argv: list[str]) -> dict:
    """Return ``{port, background, fixture}`` read from this script's own argument list.

    Hand-rolled on purpose: the two call forms this script has always honoured are a bare port and
    ``--background``, and neither may change behaviour here. ``--fixture`` is additive, and an unlisted
    flag is a refusal rather than something silently ignored — a proof run that believed it named a fresh
    directory and did not is the failure mode worth spending three lines on. The same reasoning makes
    every remaining rule additive and strict: an option is accepted exactly once, and a value is refused
    when it is absent **or blank**, because ``--fixture ''`` looks like a request for isolation while
    meaning the shared fixture — the one answer this parser must never give.

    Args:
        argv: Everything after the script name.

    Raises:
        ValueError: A flag is unknown, repeated or names no value (or a blank one), or a port is missing,
            repeated, not one plain whole number or outside 0..65535.
    """
    port, background, fixture = None, False, None
    remaining = list(argv)
    while remaining:
        item = remaining.pop(0)
        if item == BACKGROUND_OPTION:
            if background:
                raise ValueError(BACKGROUND_OPTION + ' may be named once')
            background = True
        elif item == FIXTURE_OPTION:
            if fixture is not None:
                raise ValueError(FIXTURE_OPTION + ' may be named once')
            if not remaining or not str(remaining[0]).strip():
                raise ValueError(FIXTURE_OPTION + ' needs a directory')
            fixture = remaining.pop(0)
        elif item.startswith('-'):
            raise ValueError('Unknown option: ' + item)
        else:
            if port is not None:
                raise ValueError('One port may be named, not two: ' + str(port) + ' and ' + item)
            port = whole_port(item)
    return {'port': 0 if port is None else port, 'background': background, 'fixture': fixture}


def whole_port(value: object) -> int:
    """Return *value* as a bindable port, refusing text that is not one plain whole number in range.

    `int()` alone would read `' 12 '` as 12 and `'08'` as 8, so an argument the operator did not type
    would silently become a different one; `0` stays meaningful (bind any free port).
    """
    text = str(value).strip()
    if not text.isdigit() or not text.isascii():
        raise ValueError('Port must be a plain whole number: ' + text)
    number = int(text)
    if str(number) != text or not 0 <= number <= 65535:
        raise ValueError('Port must be one whole number 0..65535: ' + text)
    return number


def child_command(port: int, fixture: str | Path | None) -> list[str]:
    """Return the background child's own argument list, forwarding an explicit fixture verbatim.

    The child re-parses what it is handed, so the fresh-fixture refusal runs in the process that will
    write the files — and the path travels as one whole argument, never as shell text. Both the script
    and an explicit fixture are given resolved, because the child runs with `cwd=ROOT` and a path
    resolved against the parent's directory would otherwise mean somewhere else.
    """
    command = [sys.executable, '-B', str(Path(__file__).resolve()), str(port)]
    if fixture is not None:
        command += [FIXTURE_OPTION, str(Path(fixture).resolve())]
    return command


def background_logs(target: Path, explicit: bool) -> tuple[Path, Path, str]:
    """Return the two log files a background launch may write, and the mode each may be opened in.

    Two rules, and no new flag to bend either of them:

    * the **shared default** fixture keeps the behaviour this script has always had — the two files sit
      inside it and are **appended** to, because a long-lived demo server's log outlives one run and the
      directory is reused on purpose;
    * an **explicit (fresh)** fixture gets the same two names as brand-new **siblings** of that
      directory, opened with exclusive create. Writing a log *inside* the directory would leave the child
      refusing the very fixture it was handed (it is no longer empty), and overwriting an earlier run's
      log is the reuse the fixture refusal exists to prevent.

    Returns:
        ``(stdout_path, stderr_path, open_mode)``, the mode being ``'a'`` or ``'x'``.

    Raises:
        ValueError: A fresh fixture's sibling log already exists — it is somebody else's run output.
    """
    if not explicit:
        return target / LOG_NAMES[0], target / LOG_NAMES[1], 'a'
    pair = tuple(target.parent / (target.name + '.' + name.removeprefix('server.')) for name in LOG_NAMES)
    for path in pair:
        if path.exists():
            raise ValueError('Refusing to overwrite an existing background log: ' + str(path)
                             + ' — name a fixture directory no earlier run used')
    return pair[0], pair[1], 'x'


def start_background(port: int, fixture: str | Path | None, *, popener=None) -> dict:
    """Fork the serving process, and return the two facts the caller needs to find it again.

    The order is the whole point, and it is the defect this function exists to keep out: prepare the
    fixture, open the logs **outside** it, and only then launch the child with the resolved absolute
    directory — so the child's own empty-directory check sees the empty directory this run created and
    needs no "allow existing" escape hatch (there is deliberately no such flag). Because the log handles
    are opened before the child starts, a refusal to create them stops the launch rather than orphaning
    a server whose output went nowhere.

    Args:
        port: The port to serve (0 binds any free one, in the child).
        fixture: ``None`` for the shared default, or the fresh directory to hand over.
        popener: The process opener, defaulting to `subprocess.Popen`. A seam for the handoff test only:
            nothing here needs a live server to check which arguments and which descriptors a child gets.

    Returns:
        ``{'pid': <child pid>, 'url_file': <fixture>/server.json}`` — the same two keys this script has
        always printed, and the address file is written by the child, never by this parent.
    """
    import subprocess
    target = fixture_directory(fixture)
    out_path, err_path, mode = background_logs(target, fixture is not None)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) | getattr(subprocess, 'DETACHED_PROCESS', 0)
    with out_path.open(mode) as out, err_path.open(mode) as err:
        child = (popener or subprocess.Popen)(child_command(port, target), cwd=ROOT,
                                             stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                             **({'creationflags': flags} if flags else {}))
        return {'pid': child.pid, 'url_file': str(target / 'server.json')}


def fixture_directory(value: str | Path | None = None) -> Path:
    """Return the fixture directory to use, creating it only when it is being started fresh.

    ``None`` is the shared default and keeps this script's original behaviour exactly: create if absent,
    reuse whatever is already there. An explicit value is a *fresh* fixture, and an existing directory
    that already holds anything is refused rather than adopted — reusing a directory is reusing somebody
    else's credentials file and state database, which is the opposite of an isolated proof run.

    Raises:
        ValueError: An explicit fixture is blank, exists and is not a directory, or exists and is not
            empty.
    """
    if value is None:
        directory = DEFAULT_FIXTURE
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    if not str(value).strip():
        raise ValueError(FIXTURE_OPTION + ' needs a directory')
    directory = Path(value)
    if directory.exists():
        if not directory.is_dir():
            raise ValueError('Refusing a fixture path that is not a directory: ' + str(directory))
        if any(directory.iterdir()):
            raise ValueError('Refusing a non-empty fixture directory: ' + str(directory)
                             + ' — pass a directory that does not exist yet, so no credential, state '
                               'database or log from an earlier run is reused')
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def policy_document(resource_id: str) -> dict:
    """The demo's one reviewed mapping, in the shape `examples/platform/verification-policy.json` shows.

    Written out rather than read from that file: the shipped example is documentation owned by the policy
    loader's card, and a demo whose seeded verdicts move when a document it does not own is edited would
    be a demo nobody can reproduce. Same twelve fields, same bounds, same `lt`/`90.0`/`300 s` meaning —
    with the demo's own detector, rule, resource and verifier names.
    """
    parameters = {'resource_id': resource_id, 'rule_id': RULE, 'artifact_sha256': ARTIFACT}
    return {'schema_version': 1, 'verifiers': [VERIFIER],
            'mappings': [{'source': DETECTOR, 'rule_id': RULE, 'rule_version': RULE_VERSION,
                          'condition': RULE, 'resource_id': resource_id,
                          'query_type': 'metric-threshold', 'parameters': dict(parameters),
                          'metric_name': METRIC, 'threshold': THRESHOLD, 'comparison': COMPARISON,
                          'window_seconds': WINDOW_SECONDS, 'artifact_sha256': ARTIFACT}]}


def evaluation_window(end: dt.datetime) -> dict[str, str]:
    """One minute-long evaluation window ending at *end* — the shape a canonical event carries."""
    return {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}


def observation_window(start: dt.datetime, seconds: int = WINDOW_SECONDS) -> dict[str, str]:
    """One submitted observation window: exactly the captured length, opening at *start*."""
    return {'start': utc_text(start), 'end': utc_text(start + dt.timedelta(seconds=seconds))}


def receipt(resource_id: str, window: dict[str, str], value: float) -> dict:
    """The six-field receipt one read of the captured series would carry, built by the store facade.

    `build_outcome` is what both real backends call, so the query kind, the approved parameters, the
    window, the expiry and the row count are the facade's own answers and not a shape invented here.
    """
    outcome = facade.build_outcome(
        facade.QUERY_KINDS['metric-threshold'],
        {'resource_id': resource_id, 'rule_id': RULE, 'artifact_sha256': ARTIFACT},
        Window(start=window['start'], end=window['end']),
        [MetricSample(name=METRIC, value=value, resource_id=resource_id,
                      labels={'resource_id': resource_id}, timestamp=window['start'])])
    return outcome.receipt.as_dict()


def rows(resource_id: str, window: dict[str, str], value: float) -> list[dict]:
    """The one claimed sample row for that window, stamped inside it and after the terminal instant."""
    return [{'resource_id': resource_id, 'metric_name': METRIC,
             'observed_at': utc_text(dt.datetime.fromisoformat(window['start'])
                                     + dt.timedelta(seconds=60)),
             'value': value}]


def statement(execution_id: str, binding_id: str, window: dict[str, str], *,
              outcome: str = 'available', read_receipt: dict | None = None,
              samples: list[dict] | None = None) -> dict:
    """One submitted observation: the six record keys and nothing else.

    No verdict, threshold or reason appears here — the server derives those. Filing through
    `Store.put_verification` rather than by writing a row is the point: what the demo shows is what the
    real write path produces, including the id the record is readable back by.
    """
    return {'execution_id': execution_id, 'binding_id': binding_id, 'window': window,
            'outcome': outcome, 'receipt': read_receipt, 'samples': [] if samples is None else samples}


def seed(store: Store, gate, resource_id: str) -> None:
    """File the synthetic history once, in the order the record reads depend on.

    Every instant is derived from one seed-time clock reading and lies in the past by the time anything
    reads it, so the *shape* of the history — a bound signal, an approved action, a succeeded execution, a
    reading still above the reviewed threshold — is the same on every host. Nothing here is random.
    """
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = utc_text(now + dt.timedelta(hours=23))
    producer, proposer = Actor(DETECTOR, 'producer'), Actor(PROPOSER, 'proposer')
    human, runner = Actor(OPERATOR, 'human'), Actor(RUNNER, 'executor')
    verifier = Actor(VERIFIER, 'producer')
    store.put_evidence({'sample_id': 'operator-demo', 'observed_at': utc_text(now), 'ok': True,
                        'value': False}, producer)

    # 1. A firing reading of the series the reviewed mapping is about. Intaken first so it is the *older*
    #    of the two events this incident holds, and so `records('events')` still answers with the
    #    availability event first, as the existing operator checker expects.
    fired_at = now - dt.timedelta(minutes=30)
    signal = store.intake(detections.event(
        DETECTOR, resource_id, RULE, 'threshold', 'firing', evaluation_window(fired_at),
        {'resource_id': resource_id, 'rule_id': RULE, 'artifact_sha256': ARTIFACT},
        query_type='metric-threshold', version=RULE_VERSION), producer, now=fired_at)

    # 2. The action that ran to completion. Proposal-time capture binds it to the signal above, and the
    #    binding id is what a submitted observation must name — read back here through the same public
    #    read an operator's client would use, not recomputed.
    verified = store.propose_action({'retry_key': VERIFIED_RETRY_KEY,
                                     'incident_id': signal['incident_id'], 'action': 'inspect-synthetic',
                                     'version': '1', 'targets': [resource_id], 'parameters': {},
                                     'evidence': [signal['event_id']], 'expires_at': expires_at},
                                    proposer, gate, now=now - dt.timedelta(minutes=28))
    store.decide(verified['action_id'], 'approved', human, now=now - dt.timedelta(minutes=27))
    claim = store.claim_action(verified['action_id'], runner, gate, now=now - dt.timedelta(minutes=26))
    terminal = now - dt.timedelta(minutes=25)
    store.execution_outcome(claim['execution_id'], 'succeeded', runner, claim['runner_token'], now=terminal)
    binding_id = store.get_verification_binding(verified['action_id'], human)['binding_id']

    # 3. Two saved checks of that one execution, in two different windows, so the id list holds more than
    #    one entry and the second says something different from the first. Both windows open after the
    #    execution went terminal, are exactly the captured length, and are over by the instant the
    #    server judges them at — which is what makes them history rather than a live re-check.
    first, second_window = observation_window(terminal + dt.timedelta(minutes=1)), \
        observation_window(terminal + dt.timedelta(minutes=6))
    judged_at = now - dt.timedelta(minutes=10)
    store.put_verification(statement(claim['execution_id'], binding_id, first,
                                     read_receipt=receipt(resource_id, first, STILL_FIRING),
                                     samples=rows(resource_id, first, STILL_FIRING)),
                           verifier, now=judged_at)
    store.put_verification(statement(claim['execution_id'], binding_id, second_window,
                                     outcome='unavailable'), verifier, now=judged_at)

    # 4. A second terminal execution with nothing ever submitted for it: the empty-history answer has to
    #    come from the server, not from an injected reply.
    unverified = store.propose_action({'retry_key': UNVERIFIED_RETRY_KEY,
                                       'incident_id': signal['incident_id'], 'action': 'inspect-synthetic',
                                       'version': '1', 'targets': [resource_id], 'parameters': {},
                                       'evidence': [signal['event_id']], 'expires_at': expires_at},
                                      proposer, gate, now=now - dt.timedelta(minutes=12))
    store.decide(unverified['action_id'], 'approved', human, now=now - dt.timedelta(minutes=11))
    runner_claim = store.claim_action(unverified['action_id'], runner, gate,
                                      now=now - dt.timedelta(minutes=11))
    store.execution_outcome(runner_claim['execution_id'], 'succeeded', runner,
                            runner_claim['runner_token'], now=now - dt.timedelta(minutes=10))

    # 5. Last, and therefore first in every record read: the availability event the demo has always fired
    #    and the approval still waiting on it. Same condition key as the signal above (source, rule,
    #    version, resource, condition) with a newer watermark, so it updates that one open incident
    #    instead of opening a second one — the open-incident count the existing checker reads stays one.
    availability = store.intake(detections.event(
        DETECTOR, resource_id, RULE, 'availability', 'firing', evaluation_window(now),
        {'sample_id': 'operator-demo'}, query_type='gatus-result', version=RULE_VERSION), producer)
    store.propose_action({'retry_key': PENDING_RETRY_KEY, 'incident_id': availability['incident_id'],
                          'action': 'inspect-synthetic', 'version': '1', 'targets': [resource_id],
                          'parameters': {}, 'evidence': [availability['event_id']],
                          'expires_at': expires_at}, proposer, gate)


def app(directory: str | Path | None = None, *, policy: object = MOUNT_DEMO_POLICY):
    """Build the demo ASGI app over `directory`, seeding it the first time it is opened.

    This function composes over a directory it is handed; refusing to adopt a directory that already
    holds somebody's state is the entry point's job, and it is done by :func:`fixture_directory`, which
    ``__main__`` calls before it gets here. A caller that wants to serve the *same* fixture twice — the
    way the fixture tests do, to show history outliving a mounted policy — therefore can, and a caller
    that runs the script does not get to reuse one.

    Args:
        directory: The fixture directory to serve, or ``None`` for the shared default (reused as it
            always was).
        policy: The verification policy to mount. The default mounts the demo's own reviewed mapping,
            which is what lets the proposal above bind and an observation be judged. Pass ``None`` to
            serve the very same file with no policy mounted — the case the operator history UI has to
            survive, because "this deployment mounts no verification policy" is not "this deployment has
            no verification history".

    Returns:
        The operator app (the platform API behind the same-origin static shell).
    """
    directory = DEFAULT_FIXTURE if directory is None else Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    declaration = read_document(ROOT / 'examples/inventory/declared.yaml')
    declaration['resources'][0]['attributes']['remediation_enabled'] = True
    resource_id = declaration['resources'][0]['id']
    index = directory / 'inventory.db'
    if not index.exists():
        build(declaration, index, 'operator-synthetic-fixture')
    store = Store(directory / 'state.db',
                  verification_policy=(VerificationPolicy(policy_document(resource_id))
                                       if policy is MOUNT_DEMO_POLICY else policy))
    gate = action_policy(index, {'inspect-synthetic': {'version': '1',
                                                       'parameters': {'type': 'object',
                                                                      'additionalProperties': False}}})
    credentials = directory / 'credentials.json'
    if credentials.exists():
        auth = json.loads(credentials.read_text())
    else:
        # No producer row on purpose. The demo mounts a policy so history can be *seeded* through the
        # store, and mounting one is what lets an allowlisted producer write; the two tokens handed out
        # here read, and one of them decides an approval. Nothing here submits an observation.
        auth = [{'identity': OPERATOR, 'role': 'human', 'token': secrets.token_urlsafe(32)},
                {'identity': READER, 'role': 'reader', 'token': secrets.token_urlsafe(32)}]
        credentials.write_text(json.dumps(auth, indent=2) + '\n')
        seed(store, gate, resource_id)
    return with_ui(create_app(store, auth, gate, index_path=index))


if __name__ == '__main__':
    settings = options(sys.argv[1:])
    if settings['background']:
        print(json.dumps(start_background(settings['port'], settings['fixture'])))
        raise SystemExit(0)
    import uvicorn
    import socket
    target = fixture_directory(settings['fixture'])
    application = app(target)
    sock = socket.socket()
    sock.bind(('127.0.0.1', settings['port']))
    port = sock.getsockname()[1]
    (target / 'server.json').write_text(json.dumps({'url': 'http://127.0.0.1:' + str(port)}) + '\n')
    uvicorn.Server(uvicorn.Config(application, host='127.0.0.1', port=port, access_log=False)).run(sockets=[sock])
