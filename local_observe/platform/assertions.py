"""Named, bounded verdicts; details never contain response values or configuration secrets.

Gatus owns HTTP, DNS, TLS and API probing (gatus for synthetics). Their v0.1 transport engines
are not ported; dead code excludes browser transactions. These checks also accept
an injected in-memory subject, but the Gatus adapter only consumes measured
conditionResults, not invented response headers or bodies.
"""
from dataclasses import dataclass
from collections.abc import Iterable
from itertools import islice
import math
from typing import Any, Protocol

from .state import StateError, label

MAX_ASSERTIONS = 16


def finite_number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def safe_name(name: str) -> str:
    label(name)
    if len(name) > 64:
        raise StateError('Assertion name exceeds 64 characters')
    return name


@dataclass(frozen=True)
class AssertionResult:
    name: str
    ok: bool
    detail: str

    def __post_init__(self):
        safe_name(self.name)
        if (type(self.ok) is not bool or self.detail not in ('passed', 'failed', 'not measured')
                or self.ok != (self.detail == 'passed')):
            raise StateError('Invalid assertion result')


class Assertion(Protocol):
    def check(self, subject: Any) -> AssertionResult: ...


@dataclass(frozen=True)
class CheckReport:
    ok: bool
    results: list[AssertionResult]

    @property
    def failed_names(self) -> list[str]:
        return [result.name for result in self.results if not result.ok]


def evaluate(subject: Any, assertions: Iterable[Assertion]) -> CheckReport:
    checks = list(islice(assertions, MAX_ASSERTIONS + 1))
    if not 1 <= len(checks) <= MAX_ASSERTIONS:
        raise StateError('Expected 1..16 assertions')
    results = [check.check(subject) for check in checks]
    if any(not isinstance(result, AssertionResult) for result in results):
        raise StateError('Invalid assertion result')
    if len({result.name for result in results}) != len(results):
        raise StateError('Duplicate assertion name')
    return CheckReport(all(result.ok for result in results), results)


def verdict(name: str, measured: bool, ok: bool) -> AssertionResult:
    return AssertionResult(name, measured and ok,
                           ('passed' if ok else 'failed') if measured else 'not measured')


@dataclass(frozen=True)
class StatusIs:
    expected: int
    name: str = 'status'

    def __post_init__(self):
        safe_name(self.name)
        if type(self.expected) is not int or not 100 <= self.expected <= 599:
            raise StateError('Invalid expected status')

    def check(self, subject: Any) -> AssertionResult:
        actual = getattr(subject, 'status', None)
        return verdict(self.name, type(actual) is int and 100 <= actual <= 599,
                       actual == self.expected)


@dataclass(frozen=True)
class HeaderEquals:
    header: str
    expected: str
    name: str = 'header'

    def __post_init__(self):
        safe_name(self.name)
        if (not isinstance(self.header, str) or not self.header or len(self.header) > 128
                or not isinstance(self.expected, str) or len(self.expected) > 4096):
            raise StateError('Invalid header expectation')

    def check(self, subject: Any) -> AssertionResult:
        headers = getattr(subject, 'headers', None)
        if (not isinstance(headers, dict) or len(headers) > 256
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())):
            return verdict(self.name, False, False)
        values = [v for k, v in headers.items() if k.lower() == self.header.lower()]
        return verdict(self.name, True, len(values) == 1 and values[0] == self.expected)


@dataclass(frozen=True)
class BodyContains:
    needle: str
    name: str = 'body'

    def __post_init__(self):
        safe_name(self.name)
        if not isinstance(self.needle, str) or not 1 <= len(self.needle) <= 4096:
            raise StateError('Invalid body expectation')

    def check(self, subject: Any) -> AssertionResult:
        body = getattr(subject, 'body', None)
        measured = isinstance(body, str) and len(body) <= 1048576
        return verdict(self.name, measured, measured and self.needle in body)


@dataclass(frozen=True)
class TimingUnder:
    phase: str
    budget_ms: float
    name: str = 'timing'

    def __post_init__(self):
        safe_name(self.name)
        safe_name(self.phase)
        if not finite_number(self.budget_ms) or self.budget_ms <= 0:
            raise StateError('Invalid timing budget')

    def check(self, subject: Any) -> AssertionResult:
        timing = getattr(subject, 'timing', None)
        value = timing.get(self.phase) if isinstance(timing, dict) else None
        measured = finite_number(value) and value >= 0
        return verdict(self.name, measured, measured and value <= self.budget_ms)


def condition_mapping(mapping: Any) -> dict[str, str]:
    """Local expression -> public safe name. Expressions never leave this seam."""
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= MAX_ASSERTIONS:
        raise StateError('Expected 1..16 condition mappings')
    for expression, name in mapping.items():
        if not isinstance(expression, str) or not 1 <= len(expression) <= 4096:
            raise StateError('Invalid condition mapping')
        safe_name(name)
    if len(set(mapping.values())) != len(mapping):
        raise StateError('Duplicate assertion name')
    return dict(mapping)


def condition_report(row: dict[str, Any], mapping: dict[str, str]) -> CheckReport:
    """Pinned Gatus v5.36.0 conditionResults objects have condition/success fields."""
    mapping = condition_mapping(mapping)
    raw = row.get('conditionResults', [])
    if not isinstance(raw, list) or len(raw) > MAX_ASSERTIONS:
        raise StateError('Invalid bounded Gatus conditions')
    measured = {}
    for item in raw:
        if (not isinstance(item, dict) or set(item) != {'condition', 'success'}
                or not isinstance(item['condition'], str) or not 1 <= len(item['condition']) <= 4096
                or type(item['success']) is not bool or item['condition'] in measured):
            raise StateError('Invalid Gatus condition result')
        measured[item['condition']] = item['success']
    results = [verdict(name, expression in measured, measured.get(expression, False))
               for expression, name in mapping.items()]
    return CheckReport(all(result.ok for result in results), results)
