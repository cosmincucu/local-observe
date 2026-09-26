"""Reference Homepage configuration; private destinations enter through an overlay."""
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit


def configuration(operator_url: str, overview_url: str, dashboards: Sequence[dict[str, Any]] = (),
                  consoles: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
    for url in (operator_url, overview_url):
        parsed = urlsplit(url)
        if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError('Expected explicit non-credential service URL')
    def widget(fields):
        return {'type': 'customapi', 'url': overview_url, 'refreshInterval': 15000,
            'headers': {'Authorization': 'Bearer {{HOMEPAGE_FILE_OVERVIEW_TOKEN}}'},
            'mappings': [{'field': field, 'label': label, 'format': 'text'} for field, label in fields]}
    services = [{'Platform': [
        {'Incidents and approvals': {'href': operator_url, 'icon': 'mdi-alert-circle-outline', 'widget': widget([
            ('open_incidents', 'Open incidents'), ('pending_approvals', 'Approvals'),
            ('pending_deliveries', 'Queued'), ('dead_deliveries', 'Failed delivery')])}},
        {'Backup and jobs': {'href': operator_url, 'icon': 'mdi-backup-restore', 'widget': widget([
            ('backup_display', 'Verified backup'), ('jobs_display', 'Observed job failures'),
            ('jobs_status', 'Job coverage')])}},
        {'Resident model': {'icon': 'mdi-brain', 'widget': widget([('model_display', 'Model')])}}]},
        {'Dashboards': list(dashboards)}, {'Consoles': list(consoles)}]
    settings = {'title': 'local-observe', 'theme': 'light', 'color': 'gray', 'headerStyle': 'clean',
        'statusStyle': 'dot', 'hideVersion': True,
        'layout': {'Platform': {'tab': 'Overview', 'style': 'row', 'columns': 3},
                   'Dashboards': {'tab': 'Observability', 'style': 'row', 'columns': 3},
                   'Consoles': {'tab': 'Consoles', 'initiallyCollapsed': True, 'style': 'row', 'columns': 3}}}
    return {'services.yaml': services, 'settings.yaml': settings, 'widgets.yaml': [], 'bookmarks.yaml': [],
            'docker.yaml': {}, 'kubernetes.yaml': {}, 'proxmox.yaml': {}}
