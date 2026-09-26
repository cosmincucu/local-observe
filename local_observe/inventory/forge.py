"""Gitea review-branch publication, resumable by remote branch/file identity."""
import base64
import json
import re
from typing import Any
import urllib.parse

from local_observe.http import JsonClient

from .validation import InvalidInventory, canonical, declared, digest


class ForgeError(ValueError):
    pass


def segment(value: str) -> str:
    return urllib.parse.quote(value, safe='')


def publish(client: JsonClient, repository: str, base_branch: str, path: str,
            proposal: dict[str, Any]) -> dict[str, Any]:
    """Create a review PR only. No merge, main-branch writes, force-push or deletion."""
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ForgeError('Expected explicit owner/repository')
    if (not re.fullmatch(r'[A-Za-z0-9_./-]+', path)
            or any(part in ('', '.', '..') for part in path.split('/'))
            or not path.endswith(('.yaml', '.json'))):
        raise ForgeError('Expected declared inventory file path')
    if not base_branch or base_branch.startswith('local-observe/discovery/'):
        raise ForgeError('Invalid target branch')
    if proposal.get('status') != 'needs_review' or not re.fullmatch('[a-f0-9]{64}', proposal.get('proposal_id', '')):
        raise ForgeError('Expected a review-only discovery proposal')
    resource = proposal['resource']
    declared({'schema_version': 1, 'resources': [resource]})
    prefix = '/api/v1/repos/' + '/'.join(segment(part) for part in repository.split('/'))
    branch = 'local-observe/discovery/' + digest([proposal['proposal_id'], repository, path])[:32]
    marker = 'local-observe-proposal:' + digest(proposal)
    content_path = prefix + '/contents/' + '/'.join(segment(part) for part in path.split('/'))

    def call(method, suffix, payload=None, allowed=(200,)):
        status, body = client.request(method, suffix, payload)
        if status not in allowed:
            raise ForgeError('Forge operation failed with HTTP ' + str(status) + '; reconcile before retry')
        return status, body

    # A deterministic branch and exact marker survive a lost create-PR response.
    existing = None
    for page in range(1, 21):
        _, pulls = call('GET', prefix + '/pulls?' + urllib.parse.urlencode({'state': 'all', 'limit': 50, 'page': page}))
        if not isinstance(pulls, list):
            raise ForgeError('Unexpected pull-request response')
        for pull in pulls:
            if pull.get('head', {}).get('ref') == branch and pull.get('base', {}).get('ref') == base_branch:
                if marker not in (pull.get('body') or ''):
                    raise ForgeError('Existing branch PR differs; human review required')
                existing = pull
        if len(pulls) < 50:
            break
    else:
        raise ForgeError('PR scan bound exceeded; do not create duplicates')
    if existing:
        return {'status': 'existing', 'number': existing['number'], 'url': existing['html_url'], 'branch': branch}

    status, branch_info = call('GET', prefix + '/branches/' + segment(branch), allowed=(200, 404))
    if status == 404:
        _, base_info = call('GET', prefix + '/branches/' + segment(base_branch))
        _, branch_info = call('POST', prefix + '/branches',
                              {'new_branch_name': branch, 'old_ref_name': base_info['commit']['id']},
                              allowed=(201,))
    content_status, content = call('GET', content_path + '?ref=' + segment(branch), allowed=(200, 404))
    from .validation import UniqueLoader
    import yaml
    try:
        raw = base64.b64decode(content['content']) if content_status == 200 else b'{"schema_version":1,"resources":[]}'
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('too large')
        document = declared(yaml.load(raw.decode(), Loader=UniqueLoader))
    except (KeyError, ValueError, yaml.YAMLError) as exc:
        raise ForgeError('Forge inventory content is invalid') from exc
    matches = [item for item in document['resources'] if item['id'] == resource['id']]
    if matches and matches != [resource]:
        raise ForgeError('Existing proposal resource differs; refuse overwrite')
    if not matches:
        document['resources'].append(resource)
        declared(document)
        encoded = base64.b64encode((json.dumps(document, indent=2) + '\n').encode()).decode()
        change = {'branch': branch, 'content': encoded, 'message': 'Propose discovered inventory resource\n\n' + marker}
        if content_status == 200:
            change['sha'] = content['sha']
        call('PUT' if content_status == 200 else 'POST', content_path, change, allowed=(200, 201))
    _, pull = call('POST', prefix + '/pulls', {'base': base_branch, 'head': branch,
        'title': 'Review discovered inventory resource ' + resource['id'],
        'body': 'Discovery proposal only. Verify identity, aliases and attributes before merging.\n\n'
                + marker}, allowed=(201,))
    return {'status': 'created', 'number': pull['number'], 'url': pull['html_url'], 'branch': branch}
