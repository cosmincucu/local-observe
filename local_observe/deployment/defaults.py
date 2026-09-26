"""Current generic Homepage defaults expressed as owned, stable content records."""
from typing import Any

from local_observe.platform.homepage import configuration


def package() -> dict[str, Any]:
    defaults = configuration('https://observe.example.test', 'http://platform:8002/v1/overview')
    content = []
    for number, (key, name) in enumerate((('platform', 'Platform'), ('dashboards', 'Dashboards'),
                                          ('consoles', 'Consoles'))):
        layout = defaults['settings.yaml']['layout'][name]
        content.append({'id': 'core.'+key, 'kind': 'group', 'spec': {
            'name': name, 'tab': layout['tab'], 'order': number, 'collapsed': layout.get('initiallyCollapsed', False)}})
    for number, (key, entry) in enumerate(zip(('incidents', 'backup-jobs', 'model'),
                                              defaults['services.yaml'][0]['Platform'])):
        name, config = next(iter(entry.items()))
        content.append({'id': 'core.'+key, 'kind': 'tile', 'spec': {
            'name': name, 'group': 'core.platform', 'order': number, 'config': config}})
    return {'schema_version': 1, 'name': 'core', 'version': '0.1.0-dev-content.1', 'content_contract': 1,
            'content': content}
