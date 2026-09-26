"""Digest the product source tree, for the platform's own startup source pin.

This is the one function the retired busctl job-observation worker left behind in this module. job observe standard
(decision job observation) moved that worker and the pinning half written for it -- the code check that refused
a worker loaded from an unexpected tree, and the systemd unit renderer -- to
`archive/platform-jobs/`. The digest stayed, because the **serving process** uses it:
`runtime.observe_startup` recomputes it on every platform start and refuses to serve when it differs
from the `LO_PLATFORM_CODE_SHA256` pin.

The file was named after the retired worker until busctl retirement scripts renamed it. Nothing in it talks to systemd
or to a job: it is a source-integrity helper, and the name now says so.
"""
import hashlib
from pathlib import Path


def code_digest(root: Path | str) -> str:
    """Return the SHA256 of the product source tree under *root*, as a stable per-file digest."""
    package = Path(root) / 'local_observe'
    files = sorted(package.rglob('*.py'))
    if not files or package.is_symlink() or any(p.is_symlink() for p in files):
        raise ValueError('A regular product source tree is required')
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(package).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
