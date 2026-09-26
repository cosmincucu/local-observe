"""Exercise a healthy owner-exported witness snapshot using copies and a local recorder."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_report
from _lib.require import refuse_optimized, require
from local_observe.deployment.state_copy import copy_state
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.deadman import tick


def rehearse(handoff, output):
    refuse_optimized()
    handoff, output = Path(handoff).absolute(), Path(output).absolute()
    if handoff.resolve(strict=True) != handoff or output.resolve() != output:
        raise ValueError('Symlink or non-canonical handoff/output refused')
    if output.is_relative_to(handoff) or handoff.is_relative_to(output):
        raise ValueError('Output must be separate from the handoff')
    raw = {}
    for name in ('report.json', 'witness-state.json'):
        path = handoff / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2:
            raise ValueError('Expected a bounded regular handoff file')
        with path.open('rb') as stream:
            raw[name] = stream.read(1024**2 + 1)
        if len(raw[name]) > 1024**2:
            raise ValueError('Handoff grew beyond the read bound')
    state, owner = json.loads(raw['witness-state.json']), json.loads(raw['report.json'])
    source_hash = hashlib.sha256(raw['witness-state.json']).hexdigest()
    if (owner.get('schema_version') != 1 or owner.get('state_sha256') != source_hash
            or owner.get('state_bytes') != len(raw['witness-state.json'])
            or owner.get('credentials_read') is not False or owner.get('service_changed') is not False
            or owner.get('pending_count') != 0
            or not re.fullmatch('[a-f0-9]{64}', owner.get('unit_sha256', ''))):
        raise ValueError('Handoff receipt differs or exceeds the read-only scope')
    if (set(state) != {'last_check', 'failed_since', 'incident_id', 'pending'}
            or state['failed_since'] is not None or state['incident_id'] is not None
            or state['pending'] != [] or not state['last_check']):
        raise ValueError('This rehearsal requires a healthy, empty-queue snapshot')
    now = timestamp(state['last_check'])
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    common = Path(os.path.commonpath((handoff, output)))
    if common == Path(common.anchor):
        raise ValueError('Handoff and rehearsal must share a bounded workspace')
    copy_state({'witness': (handoff / 'witness-state.json', 'json')}, common, output / 'backup')
    # The second copy is the application restore target, never the original handoff.
    backup = output / 'backup/witness.json'
    copy_state({'witness': (backup, 'json')}, output, output / 'restore')
    working = output / 'restore/witness.json'
    calls = []

    class Recorder:
        def request(self, method, *, payload, headers):
            require(method == 'POST' and headers == {'Idempotency-Key': payload['delivery_id']},
                    'The deadman POSTed out of contract: ' + str(method) + ' ' + str(headers))
            calls.append(json.loads(json.dumps(payload)))
            return 200, {'accepted': True, 'delivery_id': 'lost-ack' if len(calls) == 1 else payload['delivery_id']}

    def step(offset, healthy):
        return tick(working, healthy, Recorder(), now=now + dt.timedelta(seconds=offset), grace_seconds=120)

    require(step(1, True) == {'status': 'healthy', 'pending': 0}, 'A healthy snapshot recorded nothing to send')
    require(step(2, False) == {'status': 'grace', 'pending': 0}, 'A fresh failure did not open the grace window')
    require(step(121, False) == {'status': 'grace', 'pending': 0}, 'The grace window closed too early')
    require(not calls, 'The deadman sent inside the grace window')
    require(step(122, False) == {'status': 'unavailable', 'pending': 1},
            'The grace boundary did not queue exactly one delivery')
    persisted = json.loads(working.read_bytes())['pending'][0]
    require(persisted == calls[0], 'The persisted delivery differs from the one attempted')
    # tick reopens the file each time; a new recorder retries the same persisted ID.
    require(step(123, True) == {'status': 'healthy', 'pending': 1}, 'Recovery did not keep the queued delivery')
    require(calls[1] == calls[0], 'The retry regenerated the batch instead of replaying it')
    require(step(124, True) == {'status': 'healthy', 'pending': 0}, 'Recovery did not drain the queue')
    require(len(calls) == 3 and calls[2]['transition'] == 'resolved',
            'The recovery transition was not the third delivery')
    require(calls[0]['transition'] == 'opened' and calls[2]['incident_id'] == calls[0]['incident_id'],
            'The resolved delivery belongs to a different incident')
    require(calls[2]['delivery_id'] != calls[0]['delivery_id'], 'Opening and resolving reused one delivery ID')
    final = working.read_bytes()
    require(json.loads(final) == {'last_check': utc_text(now + dt.timedelta(seconds=124)),
                                 'failed_since': None, 'incident_id': None, 'pending': []},
            'The rehearsal did not end on a drained, healthy state')
    try:
        step(123, True)
    except ValueError:
        pass
    else:
        raise AssertionError('Backward clock should be refused')
    require(working.read_bytes() == final, 'A refused backward step still wrote the state file')
    require(all((handoff / name).read_bytes() == value for name, value in raw.items()),
            'The rehearsal modified the owner-handoff it was given')
    require(backup.read_bytes() == raw['witness-state.json'], 'The copied state differs from the source hash')
    report = {'schema_version': 1, 'status': 'pass', 'source_state_sha256': source_hash,
              'scope': ('a copy of an owner-exported witness snapshot replayed against a local recorder on this '
                        'host; it proves the copy is readable and idempotent, not that a provider accepted a message'),
              'unit_sha256': owner['unit_sha256'], 'copied_state_replay_passed': True,
              'original_handoff_unchanged': True, 'local_attempts': len(calls),
              'distinct_deliveries': len({row['delivery_id'] for row in calls}),
              'final_pending': 0, 'running_witness_code_verified': False,
              'live_restart_proven': False, 'live_notifications_sent': 0,
              'checks': ['healthy snapshot restore', 'grace boundary', 'lost acknowledgement',
                         'persisted delivery identity after reopen', 'ordered recovery', 'backward clock refusal']}
    write_report(output / 'report.json', report, replace=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--handoff', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(rehearse(args.handoff, args.output)))


if __name__ == '__main__':
    main()
