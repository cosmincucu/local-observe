"""Declared retention vs the retention the store actually applies (store facade, port of `store/retention_check.py`).

Retention is not this project's mechanism: ClickHouse expires the aged parts and SigNoz holds the
setting that tells it when (see ``components/data/store-signoz/CONTRACT.md``, "Retention"). What this
repository lacked was the *comparison*. In the source estate the declared tiers and the live store
disagreed on all three signals — metrics 90d declared against 30d live, traces 30d against 15d, logs
90d against 15d — and the divergence was invisible for months because the comparison existed and was
never once run against the store. A declared tier nobody measured against the live setting is a wish,
not a retention policy, and evidence an incident cites can expire under it.

Two halves, and the second one deliberately has no transport of its own:

* `declared` reads the operator's declared tiers from a JSON file and validates the shape;
* `live_from_session` reads what the store applies today through **the retention tool's own session**
  (``components/data/store-signoz/retention.py``), which is imported, not re-implemented. The tool
  already logs in, already refuses to guess an unclear duration unit, already re-reads after a write
  and already keeps the password out of every message; a second TTL reader here would be a second
  thing to get wrong, and the v0.1 `fetch_live_settings` was exactly that.

`diff` turns the pair into one line per divergence, empty only when nothing disagrees. A signal the
live settings do not name is a divergence, never a pass: "the store has no TTL configured" must be
visible, because it is the case where evidence expires fastest.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from collections.abc import Callable
from types import ModuleType
from typing import Any

from local_observe.store.client import SIGNALS

SCHEMA_VERSION = '1'
MAX_DECLARED_BYTES = 64 * 1024
MAX_TTL_DAYS = 3650
# Where the retention tool sits relative to this package in a checkout. An installed wheel ships no
# `components/` tree (setuptools packages only `local_observe*`), so the path is overridable and a
# missing tool is a named blocker rather than a silent fall back to a hand-rolled HTTP reader.
TOOL_RELATIVE = Path('components') / 'data' / 'store-signoz' / 'retention.py'
TOOL_ENVIRONMENT = 'LO_RETENTION_TOOL'


class RetentionRefused(ValueError):
    """Declared tiers could not be read, or the store's retention could not be established."""


def declared(path: Path | str, loader: Callable[[str], Any] | None = None) -> dict[str, int]:
    """Return the declared retention as ``{signal: ttl_hours}``, refusing anything malformed.

    The document is an operator's intent, so it is read narrowly: one JSON object, ``schema_version``
    ``"1"``, exactly the three signals, and a whole number of days per signal — the unit the retention
    tool's own ``--<signal>-days`` arguments take. Days become hours once, here, because every answer
    the store gives is in hours; an unclear value is refused rather than rounded.

    A YAML document needs a ``loader``, because PyYAML deliberately does not belong in this package
    (the facade's data model is stdlib-only); the refusal names that instead of importing it lazily
    behind the caller's back.
    """
    text = _read_bounded(Path(path))
    document = _parse(text, path, loader)
    if not isinstance(document, dict):
        raise RetentionRefused(f'{path}: the declared retention document must be one JSON object')
    unknown = sorted(set(document) - {'schema_version', 'tiers'})
    if unknown:
        raise RetentionRefused(f'{path}: unknown field(s) {", ".join(unknown)}; '
                               f'only schema_version and tiers are understood')
    if document.get('schema_version') != SCHEMA_VERSION:
        raise RetentionRefused(f'{path}: schema_version must be {SCHEMA_VERSION!r}, got '
                               f'{document.get("schema_version")!r}')
    tiers = document.get('tiers')
    if not isinstance(tiers, dict):
        raise RetentionRefused(f'{path}: tiers must be a mapping of signal to its retention')
    extra = sorted(set(tiers) - set(SIGNALS))
    if extra:
        raise RetentionRefused(f'{path}: tier(s) for unknown signal(s) {", ".join(extra)}; '
                               f'the store keeps {", ".join(SIGNALS)}')
    missing = sorted(set(SIGNALS) - set(tiers))
    if missing:
        raise RetentionRefused(f'{path}: no declared tier for {", ".join(missing)}; a signal nobody '
                               f'declared for is a signal whose evidence expiry is unknown')
    hours: dict[str, int] = {}
    for signal in SIGNALS:
        tier = tiers[signal]
        if not isinstance(tier, dict) or set(tier) - {'ttl_days'}:
            raise RetentionRefused(f'{path}: tiers.{signal} must be an object carrying only ttl_days')
        days = tier['ttl_days']
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_TTL_DAYS:
            raise RetentionRefused(f'{path}: tiers.{signal}.ttl_days must be a whole number of days '
                                   f'from 1 to {MAX_TTL_DAYS}')
        hours[signal] = days * 24
    return hours


def _read_bounded(path: Path) -> str:
    """Read one declared-retention file, refusing a missing one and an oversized one."""
    try:
        raw = path.read_bytes()
    except OSError:
        raise RetentionRefused(f'the declared retention file {path} is missing or unreadable') from None
    if len(raw) > MAX_DECLARED_BYTES:
        raise RetentionRefused(f'the declared retention file {path} exceeds {MAX_DECLARED_BYTES} bytes')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        raise RetentionRefused(f'the declared retention file {path} is not UTF-8 text') from None


def _parse(text: str, path: Path | str, loader: Callable[[str], Any] | None) -> Any:
    """Parse the document with stdlib json, or with the caller's loader for a non-JSON format."""
    if loader is not None:
        try:
            return loader(text)
        except RetentionRefused:
            raise
        except Exception as exc:
            raise RetentionRefused(f'{path}: the supplied loader could not parse the document '
                                   f'({type(exc).__name__})') from exc
    try:
        return json.loads(text)
    except ValueError:
        raise RetentionRefused(f'{path}: not JSON; a YAML declared-retention document needs an '
                               f'explicit loader, because PyYAML stays out of this package') from None


def live_from_session(session: Any) -> dict[str, int]:
    """Return what the store applies today as ``{signal: ttl_hours}``, using the retention tool's reader.

    ``session`` is the tool's own ``StoreSession`` (already logged in): one ``read(signal)`` per
    signal, whose first value is whole hours and whose second is the logs API's per-condition rules.
    This function asks nothing of the network itself and never prints a stored credential; a signal
    the store will not answer for propagates the tool's own bounded error rather than becoming a
    zero, because "unreadable" and "zero days" are different claims about the same shelf.
    """
    live: dict[str, int] = {}
    for signal in SIGNALS:
        hours, _conditions = session.read(signal)
        if isinstance(hours, bool) or not isinstance(hours, int) or hours < 1:
            raise RetentionRefused(f'the store returned an unreadable retention for {signal}')
        live[signal] = hours
    return live


def tool_module(path: Path | str | None = None) -> ModuleType:
    """Import the retention retention tool as a module, so its reader is the only TTL reader in the estate.

    The tool is a component script, not an installed module (``components/`` ships in the repository,
    never in the wheel), so it is loaded from its file. The name is registered in ``sys.modules``
    before execution because ``dataclasses``/typing lookups inside a module can need it; the path
    comes from the argument, then ``LO_RETENTION_TOOL``, then the checkout layout.
    """
    candidate = Path(path or os.environ.get(TOOL_ENVIRONMENT, '')
                     or Path(__file__).resolve().parents[2] / TOOL_RELATIVE)
    if not candidate.is_file():
        raise RetentionRefused(f'the retention tool {candidate} is not present; name it with {TOOL_ENVIRONMENT} '
                               f'or the path argument (an installed wheel ships no components/ tree)')
    name = 'local_observe_store_retention_tool'
    spec = importlib.util.spec_from_file_location(name, candidate)
    if spec is None or spec.loader is None:
        raise RetentionRefused(f'the retention tool {candidate} cannot be loaded')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise RetentionRefused(f'the retention tool {candidate} failed to load ({type(exc).__name__})') from exc
    for required in ('HttpTransport', 'StoreSession', 'read_credentials', 'validate_origin', 'SIGNALS'):
        if not hasattr(module, required):
            raise RetentionRefused(f'the retention tool {candidate} has no {required}; it is not the '
                                   f'retention tool this facade expects')
    return module


def live(origin: str, credentials_file: Path | str, *, tool: ModuleType | None = None,
         path: Path | str | None = None, allow_insecure_http: bool = False) -> dict[str, int]:
    """Read the live retention through the retention tool's session — the integration-tier entry point.

    Everything hard stays in the tool: the origin check, the login, the duration parsing, the
    redaction. Nothing here holds the password past the login call, and nothing here builds a second
    TTL client. The tool's own exit-code contract is preserved for callers that want it by using the
    tool directly; this function is for the one thing the tool does not do — hand its reading to a
    comparison (`diff`).
    """
    module = tool or tool_module(path)
    covering = getattr(module, 'SIGNALS', ())
    if set(covering) != set(SIGNALS):
        raise RetentionRefused(f'the retention tool covers {sorted(covering)} but this facade diffs '
                               f'{sorted(SIGNALS)}; a signal one of them forgets is a signal whose '
                               f'evidence expiry is unknown')
    credentials = module.read_credentials(Path(credentials_file))
    session = module.StoreSession(module.HttpTransport(module.validate_origin(
        origin, allow_insecure_http=allow_insecure_http)), credentials)
    session.login()
    return live_from_session(session)


def _reading(hours: Any) -> str:
    """Render one TTL the way the tool renders it: whole days when it divides, raw hours when not.

    A store that answers 336h is reporting 14 days and the line should read that way; one that answers
    36h must not be rounded to "1d", because the rounding is the drift a reader is hunting for.
    """
    if not isinstance(hours, int) or isinstance(hours, bool):
        return 'unreadable'
    days, remainder = divmod(hours, 24)
    return f'{days}d ({hours}h)' if not remainder else f'{hours}h'


def diff(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Return one line per divergence between declared and live retention; empty means in sync.

    A signal missing from either side is a divergence: an undeclared tier is a promise nobody wrote
    down, and a setting the store does not report is a tier nothing enforces. Values are compared as
    hours, so a store that answers in days and one that answers in hours agree only when they truly
    agree. The wording carries both units because a reader has to compare the line against a
    ``retention.yaml``-shaped declaration *and* against what the tool prints.
    """
    if not isinstance(expected, dict) or not isinstance(actual, dict):
        raise RetentionRefused('Retention diff needs two mappings of signal to ttl_hours')
    lines: list[str] = []
    for signal in SIGNALS:
        want = expected.get(signal)
        have = actual.get(signal)
        if want is None:
            lines.append(f'{signal}: no declared tier, but the store applies {_reading(have)}')
            continue
        if have is None:
            if signal in actual:
                lines.append(f'{signal}: declared {_reading(want)} but the store reports no retention '
                             f'at all, so nothing is expiring on this signal by design')
            else:
                lines.append(f'{signal}: declared {_reading(want)} but the live settings do not name it')
            continue
        if want != have:
            lines.append(f'{signal}: declared {_reading(want)} but the store applies {_reading(have)}')
    for signal in sorted(set(actual) - set(expected) - set(SIGNALS)):
        lines.append(f'{signal}: the store reports {_reading(actual[signal])} and nothing is declared for it')
    return lines
