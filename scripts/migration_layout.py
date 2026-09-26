"""Read the operator's declared source layout: the one input that says which estate to capture.

deployment separation moved the private baselines out of this checkout; privacy checks moves the estate out of the
code that
produces them. Every path, host, service name, tile title and endpoint the migration capture used to
hard-code now arrives in ``source-layout.json``, which lives beside the baselines in the operator's
directory (``LO_MIGRATION_BASELINE_DIR`` / ``--baseline-dir``) and is validated once, here. A missing
key is a refusal naming that key and never a default: a default path is exactly how one person's
workstation ended up baked into three shipped scripts.
"""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import sys
from typing import Any
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_migration import BASELINE_ENV, baseline_directory   # noqa: E402

# The one operator file that names an estate. It travels inside the capture it produced, so only the
# capture reads it here and every later reader (drift gate, candidate preparer) reads the copy.
LAYOUT_NAME = 'source-layout.json'
LAYOUT_VERSION = 1
# Keys whose value is a path inside the operator checkout, and so takes the `relative_source` rules.
PATH_FIELDS = ('homepage_services', 'dashboard_directory', 'mcp_tool_surface', 'deploy_map')
# Every key is required. `preserved_services`, `tile_dispositions`, `tile_availability` and
# `widget_status_tiles` may hold nothing at all — "this installation declares none" is a decision — but the
# key must be present, because a declared-empty list and a forgotten one are different failures and
# only the first is allowed through.
REQUIRED_KEYS = ('schema_version', 'homepage_services', 'dashboard_directory', 'dashboard_group_prefix',
                 'collector_configs', 'mcp_tool_surface', 'mcp_contract_sets', 'legacy_mcp_endpoint',
                 'deploy_map', 'preserved_services', 'deployment', 'tile_dispositions',
                 'tile_availability', 'widget_status_tiles')
DEPLOYMENT_KEYS = ('id', 'title', 'theme', 'color')


def layout_file(baseline_dir: Path | None = None, name: str = LAYOUT_NAME) -> Path:
    """Return the layout file inside the operator's baseline directory, refusing anything else.

    Mirrors `check_migration.baseline_file`: a configured directory holding no layout is refused by
    name rather than reported as drift, because a missing operator input and a changed source file are
    different failures. `name` stays a bare file name so a caller cannot reach outside that directory.
    """
    candidate = Path(name)
    if candidate.is_absolute() or len(candidate.parts) != 1:
        raise ValueError('The source layout must be one file name inside the baseline directory, not a path: '
                         + name)
    path = baseline_directory(baseline_dir)/candidate.name
    if not path.is_file():
        raise ValueError('Set --baseline-dir or ' + BASELINE_ENV + " to the directory in the operator's "
                         'repository holding ' + candidate.name + '; ' + str(path.parent) + ' has no such file.')
    return path


def relative_source(value: Any, field: str) -> str:
    """Return `value` as a POSIX path relative to the source checkout, refusing every other form.

    An absolute path names one machine, a backslash names one operating system, ``..`` reaches out of
    the checkout the operator selected, and an empty string names nothing. The four refusals are the
    whole of the rule; no existence check happens here because the capture hashes the file it joins.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(field + ' must be a non-empty path relative to the source checkout, not ' + repr(value))
    if '\\' in value:
        raise ValueError(field + ' must use forward slashes: ' + repr(value))
    if '..' in value:
        raise ValueError(field + ' may not contain ".." — it stays inside the source checkout: ' + repr(value))
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise ValueError(field + ' must be relative to the source checkout, an absolute path names one '
                         'machine: ' + repr(value))
    return PurePosixPath(value).as_posix()


def validate_layout(document: Any) -> dict[str, Any]:
    """Return the validated, normalised form of one source-layout document, refusing otherwise.

    Every refusal is a `ValueError` naming the offending key, because the operator edits this file by
    hand and the useful message is the one that says which key and why.
    """
    if not isinstance(document, dict):
        raise ValueError(LAYOUT_NAME + ' must be one JSON object, not ' + type(document).__name__)
    missing = [key for key in REQUIRED_KEYS if key not in document]
    if missing:
        raise ValueError(LAYOUT_NAME + ' is missing ' + ', '.join(missing) + ': every key is required, '
                         'and a declared-empty list is not the same as a forgotten one')
    unknown = sorted(key for key in document if key not in REQUIRED_KEYS)
    if unknown:
        raise ValueError(LAYOUT_NAME + ' carries key(s) this version does not admit: ' + ', '.join(unknown))
    version = document['schema_version']
    if isinstance(version, bool) or version != LAYOUT_VERSION:
        raise ValueError('schema_version must be ' + str(LAYOUT_VERSION) + ' for this reader, not ' + repr(version))
    layout: dict[str, Any] = {'schema_version': LAYOUT_VERSION}
    # Checked on the value as written: `PurePosixPath` would tidy a trailing separator away and the
    # capture joins dashboard file names with an explicit '/', so a double one must be refused here.
    if isinstance(document['dashboard_directory'], str) and document['dashboard_directory'].endswith('/'):
        raise ValueError('dashboard_directory must not end in "/": the capture joins each dashboard file '
                         'name with one separator, and a trailing slash would hash a double one')
    for field in PATH_FIELDS:
        layout[field] = relative_source(document[field], field)
    layout['dashboard_group_prefix'] = _text(document['dashboard_group_prefix'], 'dashboard_group_prefix')
    layout['legacy_mcp_endpoint'] = _endpoint(document['legacy_mcp_endpoint'])
    layout['collector_configs'] = _collectors(document['collector_configs'])
    layout['mcp_contract_sets'] = _names(document['mcp_contract_sets'], 'mcp_contract_sets', may_be_empty=False)
    layout['preserved_services'] = _names(document['preserved_services'], 'preserved_services')
    layout['widget_status_tiles'] = _names(document['widget_status_tiles'], 'widget_status_tiles')
    layout['tile_dispositions'] = _text_map(document['tile_dispositions'], 'tile_dispositions')
    layout['tile_availability'] = _text_map(document['tile_availability'], 'tile_availability')
    layout['deployment'] = _deployment(document['deployment'])
    return layout


def read_layout(baseline_dir: Path | None = None, name: str = LAYOUT_NAME) -> dict[str, Any]:
    """Read and validate the operator's source layout; the only reader is `prepare_migration`.

    The capture copies the validated document into the baseline it writes, so the drift gate and the
    candidate preparer never open a second operator file and can never disagree with the capture about
    which estate was described.
    """
    path = layout_file(baseline_dir, name)
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(LAYOUT_NAME + ' could not be read as JSON (' + str(exc) + '): ' + str(path)) from exc
    return validate_layout(document)


def _text(value: Any, field: str) -> str:
    """Return `value` when it is a non-empty string, refusing it otherwise."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(field + ' must be a non-empty string, not ' + repr(value))
    return value


def _names(value: Any, field: str, may_be_empty: bool = True) -> list[str]:
    """Return `value` when it is a list of non-empty strings (optionally empty as a list)."""
    if not isinstance(value, list):
        raise ValueError(field + ' must be a list of names, not ' + type(value).__name__)
    if not may_be_empty and not value:
        raise ValueError(field + ' must name at least one entry: an empty list here would pass a '
                         'contract set that was never captured')
    return [_text(item, field + ' entry') for item in value]


def _text_map(value: Any, field: str) -> dict[str, str]:
    """Return `value` when it is a mapping of non-empty strings to non-empty strings."""
    if not isinstance(value, dict):
        raise ValueError(field + ' must be an object mapping a tile title to one sentence, not '
                         + type(value).__name__)
    return {_text(key, field + ' key'): _text(item, field + ' value') for key, item in value.items()}


def _collectors(value: Any) -> list[dict[str, str]]:
    """Return the declared collector configs: a non-empty list of ``{host, path}`` pairs."""
    if not isinstance(value, list) or not value:
        raise ValueError('collector_configs must be a non-empty list of {host, path} objects')
    collectors = []
    for index, item in enumerate(value):
        field = 'collector_configs[' + str(index) + ']'
        if not isinstance(item, dict) or set(item) != {'host', 'path'}:
            raise ValueError(field + ' must carry exactly host and path, not ' + repr(item))
        collectors.append({'host': _text(item['host'], field + '.host'),
                           'path': relative_source(item['path'], field + '.path')})
    return collectors


def _deployment(value: Any) -> dict[str, str]:
    """Return the deployment identity the candidate preparer builds: ``id``, ``title``, ``theme``, ``color``.

    This is the estate's own name and nothing here may re-spell it: the shipped product code must not
    carry it, so it arrives declared and the preparer copies it through.
    """
    if not isinstance(value, dict):
        raise ValueError('deployment must be an object of ' + ', '.join(DEPLOYMENT_KEYS) + ', not '
                         + type(value).__name__)
    missing = [key for key in DEPLOYMENT_KEYS if key not in value]
    if missing:
        raise ValueError('deployment is missing ' + ', '.join(missing))
    unknown = sorted(key for key in value if key not in DEPLOYMENT_KEYS)
    if unknown:
        raise ValueError('deployment carries key(s) the candidate does not use: ' + ', '.join(unknown))
    return {key: _text(value[key], 'deployment.' + key) for key in DEPLOYMENT_KEYS}


def _endpoint(value: Any) -> str:
    """Return the declared legacy MCP endpoint when it is an http(s) URL with a host.

    Not a path: `relative_source` would refuse it, and the capture stores it as an address to compare
    against, never as a file to open.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError('legacy_mcp_endpoint must be a non-empty http(s) URL, not ' + repr(value))
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.netloc:
        raise ValueError('legacy_mcp_endpoint must be an http(s) URL carrying a host: ' + repr(value))
    return value
