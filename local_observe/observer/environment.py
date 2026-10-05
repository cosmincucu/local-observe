"""Protected JSON settings; no shell evaluation, ambient merge or raw credential values."""
from __future__ import annotations

import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

from .contract import require, strict_json
from .journal import private_directory


ALLOWED = frozenset({'LO_CLICKHOUSE_URL', 'LO_CLICKHOUSE_READ_USER', 'LO_CLICKHOUSE_READ_PASSWORD_FILE',
                     'LO_AI_BASE_URL', 'LO_AI_API_KEY_FILE', 'LO_AI_MODEL', 'LO_AI_MODEL_FAST',
                     'LO_AI_OUT_OF_LAN', 'LO_AI_CAPTURE', 'LO_AI_POLICY', 'LO_AI_CAPABILITY', 'LO_AI_BUDGET',
                     'LO_INTERNAL_ALLOW_HTTP', 'LO_OBSERVER_MODEL_PROVIDER', 'LO_OBSERVER_MODEL_VERSION',
                     'LO_OBSERVER_MODEL_DEPLOYMENT', 'LO_OBSERVER_MODEL_ROUTES'})
PATHS = frozenset({'LO_CLICKHOUSE_READ_PASSWORD_FILE', 'LO_AI_API_KEY_FILE', 'LO_AI_POLICY',
                   'LO_AI_CAPABILITY', 'LO_AI_BUDGET', 'LO_OBSERVER_MODEL_ROUTES'})


def protected_bytes(path: str | Path, limit: int = 65536) -> bytes:
    candidate = Path(path).absolute()
    require(candidate.name not in ('.', '..'), 'invalid_protected_path')
    directory = private_directory(candidate.parent, create=False)
    try:
        fd = os.open(candidate.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'private_owned_file_required')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(limit + 1)
            require(len(raw) <= limit, 'protected_file_too_large')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def protected_json(path: str | Path, limit: int = 65536):
    return strict_json(protected_bytes(path, limit), limit, max_depth=20)


def validate_environment(value: dict) -> dict[str, str]:
    require(isinstance(value, dict) and set(value) <= ALLOWED, 'unknown_environment_setting')
    require(not value.get('LO_OBSERVER_MODEL_ROUTES') or not any(value.get(key) for key in
            ('LO_OBSERVER_MODEL_DEPLOYMENT', 'LO_OBSERVER_MODEL_PROVIDER', 'LO_OBSERVER_MODEL_VERSION')),
            'model_route_pool_ambiguous')
    for key, item in value.items():
        require(isinstance(item, str) and 1 <= len(item) <= 2048 and item == item.strip()
                and not any(ord(c) < 32 or ord(c) == 127 for c in item), 'invalid_environment_value')
        if key in PATHS:
            require(Path(item).is_absolute() and '..' not in Path(item).parts, 'absolute_setting_path_required')
        elif key in ('LO_INTERNAL_ALLOW_HTTP', 'LO_AI_OUT_OF_LAN', 'LO_AI_CAPTURE'):
            require(item in ('0', '1'), 'invalid_environment_flag')
        elif key in ('LO_CLICKHOUSE_URL', 'LO_AI_BASE_URL'):
            parsed = urlsplit(item)
            require(parsed.scheme in (('http', 'https') if value.get('LO_INTERNAL_ALLOW_HTTP') == '1' else ('https',))
                    and bool(parsed.hostname) and not parsed.username and not parsed.password
                    and not parsed.query and not parsed.fragment and parsed.path in ('', '/'),
                    'invalid_setting_endpoint')
        elif key == 'LO_OBSERVER_MODEL_DEPLOYMENT':
            # A gateway deployment ID names one backend: same single-token shape the guard compares.
            from .model_route import deployment_id
            require(deployment_id(item) is not None, 'invalid_environment_label')
        else:
            from .provenance import label
            require(label(item) == item, 'invalid_environment_label')
    return {**value, 'LO_AI_CAPTURE': '0'}


def load_environment(path: str | Path | None, *, ambient=None) -> dict[str, str]:
    values = os.environ if ambient is None else ambient
    return validate_environment(protected_json(path) if path else {k: v for k, v in values.items() if k in ALLOWED})
