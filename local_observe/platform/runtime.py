"""Startup observations from the serving process, not a separate inspection import."""
import datetime as dt
import os
from pathlib import Path
import re
import sys
from typing import Any

from .notification_safety import SAFETY_CONTRACT
from .source_pin import code_digest


def observe_startup(mode: str, sender_configured: bool) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[2]
    expected_root = os.environ.get('LO_PLATFORM_CODE_ROOT')
    expected_sha = os.environ.get('LO_PLATFORM_CODE_SHA256')
    if bool(expected_root) != bool(expected_sha):
        raise ValueError('Platform code root and SHA256 must be pinned together')
    if expected_root and (not Path(expected_root).is_absolute()
                          or Path(expected_root).resolve(strict=True) != root):
        raise ValueError('Platform loaded from an unexpected source root')
    if expected_sha and not re.fullmatch('[a-f0-9]{64}', expected_sha):
        raise ValueError('Invalid platform source SHA256')
    modules = {}
    for name, module in tuple(sys.modules.items()):
        if name == 'local_observe' or name.startswith('local_observe.'):
            filename = getattr(module, '__file__', None)
            if not filename or not Path(filename).resolve().is_relative_to(root / 'local_observe'):
                raise ValueError('Mixed platform module source roots')
            modules[name] = str(Path(filename).resolve())
    actual = code_digest(root)
    if expected_sha and expected_sha != actual:
        raise ValueError('Platform source digest differs from the startup pin')
    return {'schema_version': 1, 'pid': os.getpid(),
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'code_root': str(root), 'startup_source_sha256': actual,
            'source_pin_verified': bool(expected_sha), 'loaded_modules': modules,
            'notification_safety_contract': SAFETY_CONTRACT,
            'notification_mode': mode, 'sender_configured': sender_configured,
            'scope': 'startup filesystem and imported module paths; not continuous integrity attestation'}
