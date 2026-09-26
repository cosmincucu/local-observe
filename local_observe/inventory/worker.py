"""Scheduled, scoped observations; durable proposals never imply declaration approval.

This module is the only place discovery writes anything, and what it writes is observed data plus
proposal files: `discovery.ingest` appends a snapshot, `discovery.drift` compares it to the
read-only declaration index, `discovery.ageing` reports what a source stopped seeing, and
`forge.publish` opens a review PR. Declarations are promoted by a human merging that PR (discovery write policy), so
no path here reaches `index.build` or `validation.declared`. Providers hand this module
observations; they never receive the index, the proposal path or the forge client.
"""
from collections.abc import Callable
import datetime as dt
import json
import os
from pathlib import Path
from typing import Any

from local_observe.http import JsonClient
from local_observe.log import get_logger
from local_observe.platform.detection_worker import exclusive_owner, save
from . import discovery, docker_provider, kube_provider, sweep_provider
from .forge import publish
from .validation import InvalidInventory, digest, read_document, utc_text

log = get_logger(__name__)
SOURCES = ('docker', 'kube', 'sweep')


def tick(config: dict[str, Any], provider: Callable[[], dict[str, Any]] | discovery.Provider, *,
         client: JsonClient | None = None, now: dt.datetime | None = None) -> dict[str, Any]:
    """Run one scoped observation, append it, report drift and aging, and open reviews when asked.

    The provider is either a `discovery.Provider` or a callable returning an already-sealed
    document; both paths end in the same append-only ingest. Proposals are made only for
    observations named in `proposal_allowlist` that drift called undeclared, and each becomes a
    durable proposal file plus — when a forge client exists — one review pull request. Nothing here
    promotes a declaration: `ageing_grace_seconds` reports silence, and the human merge is discovery write policy.
    One optional key bounds that report: `ageing_max_aged_percent` is the share of a source's known
    population one round may age (see `discovery.ageing`), and a round over it says `ageing_capped`.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    root = Path(config['state'])
    root.mkdir(parents=True, exist_ok=True)
    path = root/'cursor.json'
    binding = digest(config)
    state = json.loads(path.read_text()) if path.exists() else {'binding': binding, 'pending': None}
    if state['binding'] != binding:
        raise ValueError('Discovery cursor configuration changed; reconcile explicitly')
    # Keep the exact snapshot across retries, including snapshot UUID and timestamp.
    if state['pending'] is None:
        # A scoped provider seals its own envelope; a bare callable already returns a document.
        produce = getattr(provider, 'snapshot', provider)
        state['pending'] = produce()
        save(path, state)
    snapshot = state['pending']
    log.debug('Observation snapshot in scope', extra={'source': snapshot.get('source'),
                                                     'snapshot_id': snapshot.get('snapshot_id')})
    database = root/('observations-'+now.strftime('%Y-%m')+'.db')
    discovery.ingest(database, snapshot, now=now)
    report = discovery.drift(config['index'], database, [snapshot['source']], now=now)
    proposals = root/'proposals'
    proposals.mkdir(exist_ok=True)
    results = []
    for item in snapshot['observations']:
        if item['observation_id'] not in config.get('proposal_allowlist', []):
            continue
        proposal_path = proposals/(digest([snapshot['source'], item['observation_id']])+'.json')
        if proposal_path.exists():
            proposal = json.loads(proposal_path.read_text())
            if proposal['observation_sha256'] != digest(item):
                log.warning('Observed resource changed since the proposal was written; review required',
                            extra={'proposal_id': proposal['proposal_id'], 'observation_id': item['observation_id']})
                results.append({'status': 'changed_observation_needs_review', 'proposal_id': proposal['proposal_id']})
                continue
        else:
            if not any(f['kind'] == 'undeclared' and f.get('observation_id') == item['observation_id']
                       for f in report['findings']):
                continue
            proposal = discovery.propose(config['index'], database, snapshot['source'],
                                         item['observation_id'], proposal_path, now=now)
        result_path = proposal_path.with_suffix('.result.json')
        if result_path.exists():
            results.append(json.loads(result_path.read_text()))
        elif client is not None:
            forge = config['forge']
            result = publish(client, forge['repository'], forge['branch'], forge['path'], proposal)
            save(result_path, result)
            results.append(result)
        else:
            results.append({'status': 'local_review_only', 'proposal_id': proposal['proposal_id']})
    save(root/'drift.json', report)
    # Aging is reported, never applied: what a source stopped seeing keeps its observed_at evidence
    # and stays in the append-only plane, and a stale source returns a status instead of a list.
    ageing_report = None
    if 'ageing_grace_seconds' in config:
        # The cap is passed only when the config names it, so an existing config keeps the default
        # rather than a copy of it that a later default change could not reach.
        cap: dict[str, Any] = {}
        if 'ageing_max_aged_percent' in config:
            cap['max_aged_percent'] = int(config['ageing_max_aged_percent'])
        ageing_report = discovery.ageing(database, snapshot['source'], now=now, grace_seconds=int(
            config['ageing_grace_seconds']), **cap)
        save(root/'ageing.json', ageing_report)
        if ageing_report['status'] == 'ageing_capped':
            log.warning('Ageing round refused: more of this source went silent in one round than the '
                        'cap allows, so nothing was concluded',
                        extra={'source': snapshot['source'],
                               'known_observations': ageing_report['known_observations'],
                               'aged_candidates': ageing_report['aged_candidates'],
                               'allowed_aged': ageing_report['allowed_aged']})
    state.update(pending=None, last_success=utc_text(now), observations=len(snapshot['observations']),
                 findings=len(report['findings']), proposals=results, database=str(database),
                 ageing=ageing_report['status'] if ageing_report else 'not-configured',
                 aged_out=len(ageing_report['aged_out']) if ageing_report else 0)
    save(path, state)
    log.info('Discovery tick finished', extra={'source': snapshot.get('source'),
                                              'observations': state['observations'],
                                              'findings': state['findings'],
                                              'proposal_results': len(results),
                                              'statuses': sorted({str(row.get('status')) for row in results})})
    return state


def provider_from_config(config: dict[str, Any]) -> Callable[[], dict[str, Any]]:
    """Build the one configured source, refusing any source whose scanner would ship here.

    Docker reads a socket the config names; Kubernetes reads a bounded listing file the operator
    captured elsewhere. A sweep is refused outright: probing needs a prober, no JSON document can
    carry a callable, and a shipped default prober would scan a network this repository does not own
    from a config file someone else reviewed. An operator who holds a prober constructs
    `sweep_provider.SweepProvider` in their own driver and passes it to `tick`.
    """
    named = [key for key in SOURCES if key in config]
    if len(named) != 1:
        raise InvalidInventory('Discovery config must name exactly one source: ' + ' or '.join(SOURCES))
    kind = named[0]
    if kind == 'sweep':
        raise InvalidInventory('A sweep needs an injected prober, which no config file can carry; '
                               'construct SweepProvider from a driver that holds one')
    if kind == 'docker':
        if not isinstance(config['docker'], dict):
            raise InvalidInventory('The docker source must name its projects, socket and data root')
        return lambda: docker_provider.snapshot(**config['docker'])
    if not isinstance(config['kube'], dict) or 'listing_file' not in config['kube']:
        raise InvalidInventory('The kubernetes source must name one bounded listing file it may read')
    settings = dict(config['kube'])
    listing = read_document(Path(settings.pop('listing_file')))
    return lambda: kube_provider.KubeProvider(listing=listing, **settings).snapshot()


def main() -> None:
    """Run one tick from LO_DISCOVERY_CONFIG, under the state directory's writer exclusion."""
    config = json.loads(Path(os.environ['LO_DISCOVERY_CONFIG']).read_text())
    root = Path(config['state'])
    root.mkdir(parents=True, exist_ok=True)
    client = None
    if config.get('forge'):
        forge = config['forge']
        client = JsonClient(forge['url'], Path(forge['token_file']).read_text().strip(), scheme='token')
    with exclusive_owner(root/'worker.lock'):
        tick(config, provider_from_config(config), client=client)


if __name__ == '__main__':
    main()
