"""Backup coverage for ``security_events``: does the store's backup unit actually contain the table?

The question v0.1 asked (`legacy:aiops/security/backup.py`) and the one this repository had never asked
about an owned table: a nightly that copies the store's data directory covers this database *if the
table's parts are inside that directory at snapshot time* — and "if" is a fact about a filesystem,
not about a manifest. An unverified claim of coverage is what this module exists to replace.

Two answers, deliberately apart, because they are checked differently and one passing does not prove
the other:

* **`coverage(root)`** — a filesystem check: the ClickHouse data directory the caller names holds
  ``data/security_events/events/``. It is *asked*, never guessed: this module ships **no default
  path**, because the product does not know where a particular deployment keeps its data and a
  hard-coded host path would make the check pass on the machine that wrote it and mean nothing
  anywhere else.
* **the volume question** — whether that directory is inside the store's backup unit — is answered in
  ``components/data/store-signoz/backup.md`` (step 4a) with the two commands that show the table's
  ``data_paths`` and the volume they sit on. It cannot be a filesystem check from here: the product
  runs in a container that does not mount the host's storage.

A table that has never been written has no parts directory, so ``coverage`` distinguishes "the
database exists and has nothing in it yet" from "there is no owned table here at all" — the first is
an empty store that will be covered when it fills, the second means the schema was never applied.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from local_observe.security.schema import DATABASE, TABLE

# ClickHouse lays a database's tables out under ``<datadir>/data/<database>/<table>/``. Both names
# are the server's convention, not this product's choice, and they are what makes the check
# meaningful: it looks where the server writes, not where a document says it might.
DATA_DIRECTORY = 'data'
ENV_DATA_ROOT = 'LO_SECURITY_EVENTS_DATA_ROOT'


class BackupCoverageRefused(ValueError):
    """Coverage could not be established; the reason names what was missing, never a host."""


@dataclass(frozen=True)
class BackupCoverage:
    """What the store's data directory said about the owned table.

    ``covered`` is the only word a backup job should branch on, and it is true only when both
    directories were *seen* — not when the check ran, not when the table was queryable. ``detail``
    states the same verdict in a sentence with the paths in it, because the next question a reader
    asks is "which directory did you look at".
    """

    covered: bool
    state: str
    database_dir: str
    table_dir: str
    detail: str

    @property
    def ok(self) -> bool:
        """The backup job's word: is the owned table inside what is being copied."""
        return self.covered

    def as_dict(self) -> dict[str, object]:
        """Return the verdict as JSON-safe text for a metric line or a job log."""
        return {'covered': self.covered, 'state': self.state, 'database_dir': self.database_dir,
                'table_dir': self.table_dir, 'detail': self.detail}


def coverage(root: Path | str) -> BackupCoverage:
    """Return whether the ClickHouse data directory at *root* actually holds the owned table.

    *root* is the server's own data directory (the path a ``clickhouse-server`` is configured with),
    not a container mount point and not a project directory: pass the value that
    ``SELECT data_paths FROM system.tables`` reports for the owned table, minus the table's own path.
    Nothing here defaults it, and a path that does not exist is a ``missing`` state rather than an
    exception — a backup job that crashes because a directory moved is a job that stops reporting
    coverage, which is the failure mode this whole module is aimed at.
    """
    base = Path(root) if isinstance(root, (str, Path)) else None
    if base is None:
        raise BackupCoverageRefused('the ClickHouse data directory must be named')
    database_dir = base / DATA_DIRECTORY / DATABASE
    table_dir = database_dir / TABLE
    if not database_dir.is_dir():
        return BackupCoverage(
            covered=False, state='missing', database_dir=str(database_dir), table_dir=str(table_dir),
            detail=f'no {DATABASE} directory under {base}: the owned schema was never applied here, so '
                   f'whatever the job copies does not include it')
    if not table_dir.is_dir():
        return BackupCoverage(
            covered=False, state='empty-database', database_dir=str(database_dir), table_dir=str(table_dir),
            detail=f'{database_dir} exists but carries no {TABLE} directory: either the table was dropped or '
                   f'it has never been written, and no merge has placed its parts on disk yet')
    return BackupCoverage(
        covered=True, state='present', database_dir=str(database_dir), table_dir=str(table_dir),
        detail=f'{table_dir} is present under the data directory the job copies, so the table is inside '
               f'that unit as of this check')


def data_root_from_environment(environ: Mapping[str, str] | None = None) -> str:
    """Return the data directory named by ``LO_SECURITY_EVENTS_DATA_ROOT``; a missing one is a refusal.

    The refusal is the design. This repository ships no host paths (synthetic naming: no estate identifiers in
    product code), so the caller — the backup hook on a particular host — must name the root, and a
    job that set nothing fails with a sentence naming the variable instead of silently checking a
    path that happens to exist on whoever wrote this file.
    """
    values = os.environ if environ is None else environ
    root = values.get(ENV_DATA_ROOT)
    if not root:
        raise BackupCoverageRefused(f'{ENV_DATA_ROOT} is not set: name the ClickHouse data directory whose '
                                    f'backup is in question, then re-run the check')
    return root


def check(environ: Mapping[str, str] | None = None) -> BackupCoverage:
    """Read the root from the environment and answer the coverage question (the job's entry point)."""
    return coverage(data_root_from_environment(environ))
