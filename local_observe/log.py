"""Structured JSON-lines logging shared by workers, clients and CLI entry points.

The contract is deliberately small: one JSON object per line on stderr holding the
fixed fields ``ts`` (UTC ISO 8601), ``level``, ``logger`` and ``event`` (the message),
plus whatever ``extra`` keys a call site supplies. Log identifiers (delivery, event,
incident, job, rule, execution), statuses, counts and durations. Never log payload
bodies, credentials, URLs carrying credentials, or environment values; call sites pass
exception *class names*, not exception text, because exception messages can echo input.
Tracebacks are emitted at DEBUG only and are dropped at every higher level.

The level comes from ``LO_LOG_LEVEL`` (a standard level name, case-insensitive; anything
else falls back to ``INFO`` so a typo cannot silence the estate's workers).
"""
from __future__ import annotations

from collections.abc import Mapping
import datetime as dt
import json
import logging
import math
import os
import sys
from typing import Any

from local_observe.inventory.validation import is_secret_key, utc_text

LEVEL_ENVIRONMENT_VARIABLE = 'LO_LOG_LEVEL'
DEFAULT_LEVEL_NAME = 'INFO'
STANDARD_LEVEL_NAMES = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
LEVELS: dict[str, int] = {name: getattr(logging, name) for name in STANDARD_LEVEL_NAMES}
FIXED_FIELDS = ('ts', 'level', 'logger', 'event')
REDACTED_PLACEHOLDER = '<redacted>'
TRUNCATED_PLACEHOLDER = '<truncated>'
UNREPRESENTABLE_PLACEHOLDER = '<unrepresentable>'
MAX_FIELD_DEPTH = 6
MAX_SEQUENCE_ITEMS = 100
MAX_SCALAR_LENGTH = 300
MAX_EVENT_LENGTH = 512
MAX_TRACEBACK_LENGTH = 4000


def _standard_fields() -> frozenset[str]:
    """Names the logging machinery owns; they are never call-site fields."""
    probe = logging.LogRecord('local_observe.log', logging.INFO, __file__, 0, 'probe', None, None)
    return frozenset(probe.__dict__) | {'asctime', 'message', 'taskName'}


STANDARD_FIELDS = _standard_fields()


def resolve_level(raw: str | None) -> int:
    """Return the level named by *raw*, falling back to ``INFO`` for any other value.

    Only the five standard level names are honoured, case-insensitively and ignoring
    surrounding space. ``NOTSET`` is rejected on purpose: a root logger with no level
    would turn "unconfigured" into "log everything", which is the opposite of failing closed.
    """
    if isinstance(raw, str) and raw.strip().upper() in LEVELS:
        return LEVELS[raw.strip().upper()]
    return LEVELS[DEFAULT_LEVEL_NAME]


def _bounded(value: Any) -> Any:
    """Coerce one scalar into a JSON-safe, length-bounded form."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else UNREPRESENTABLE_PLACEHOLDER
    if isinstance(value, str):
        return value if len(value) <= MAX_SCALAR_LENGTH else value[:MAX_SCALAR_LENGTH] + TRUNCATED_PLACEHOLDER
    try:
        text = repr(value)
    except Exception:  # a broken __repr__ must not break the process that is logging
        return UNREPRESENTABLE_PLACEHOLDER
    return text if len(text) <= MAX_SCALAR_LENGTH else text[:MAX_SCALAR_LENGTH] + TRUNCATED_PLACEHOLDER


def redacted(value: Any) -> Any:
    """Return *value* with credential-named entries replaced by ``<redacted>``.

    Mappings and sequences are walked to ``MAX_FIELD_DEPTH`` (deeper becomes
    ``<truncated>``) and sequences are capped at ``MAX_SEQUENCE_ITEMS``. Keys are matched by
    ``inventory.validation.is_secret_key``, the one predicate this module re-exports: the flattened
    name or its last word must be a credential marker, so ``claim_token`` is masked and a pointer
    name like ``token_file`` is not. The key name is kept, the value is not.
    Values that are not JSON-compatible become a bounded ``repr`` so building a log line
    can never raise.
    """
    if isinstance(value, Mapping):
        return {str(key): (REDACTED_PLACEHOLDER if is_secret_key(key) else _redacted(item, 1))
                for key, item in value.items()}
    return _redacted(value, 0)


def _redacted(value: Any, depth: int) -> Any:
    """Recursive worker for :func:`redacted` with a bounded depth."""
    if depth >= MAX_FIELD_DEPTH:
        return TRUNCATED_PLACEHOLDER
    if isinstance(value, Mapping):
        return {str(key): (REDACTED_PLACEHOLDER if is_secret_key(key) else _redacted(item, depth + 1))
                for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)[:MAX_SEQUENCE_ITEMS]
        return [_redacted(item, depth + 1) for item in items]
    return _bounded(value)


def supplied_fields(record: logging.LogRecord) -> dict[str, Any]:
    """Return only the ``extra`` keys a call site attached to *record*."""
    return {key: item for key, item in vars(record).items()
            if key not in STANDARD_FIELDS and not key.startswith('_') and key not in FIXED_FIELDS}


class JsonLinesFormatter(logging.Formatter):
    """Render one record as a single JSON object, one line, with no credential echo."""

    def format(self, record: logging.LogRecord) -> str:
        """Format *record* as ``ts``/``level``/``logger``/``event`` plus its redacted extras."""
        event = record.getMessage()
        line: dict[str, Any] = {'ts': utc_text(dt.datetime.fromtimestamp(record.created, dt.timezone.utc)),
                                'level': record.levelname, 'logger': record.name,
                                'event': event if len(event) <= MAX_EVENT_LENGTH
                                else event[:MAX_EVENT_LENGTH] + TRUNCATED_PLACEHOLDER}
        for key, value in redacted(supplied_fields(record)).items():
            line.setdefault(key, value)
        if record.exc_info is not None and record.levelno <= logging.DEBUG:
            line['traceback'] = self.formatException(record.exc_info)[:MAX_TRACEBACK_LENGTH]
        return json.dumps(line, ensure_ascii=True, allow_nan=False)


_configured = False


def configure(*, level: str | None = None) -> None:
    """Install the JSON-lines handler on the root logger once; later calls do nothing.

    :param level: an explicit level name; when omitted, ``LO_LOG_LEVEL`` is read.
    """
    global _configured
    if _configured:
        return
    root = logging.getLogger()
    if not any(isinstance(handler.formatter, JsonLinesFormatter) for handler in root.handlers):
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(JsonLinesFormatter())
        root.addHandler(stream)
    requested = os.environ.get(LEVEL_ENVIRONMENT_VARIABLE) if level is None else level
    root.setLevel(resolve_level(requested))
    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return the logger called *name*, configuring the root handler on first use."""
    configure()
    return logging.getLogger(name)
