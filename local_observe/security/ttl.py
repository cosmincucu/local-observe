"""The one place the ``security_events`` TTL numbers live, and the check that the store obeys them.

Two numbers, stated once (security store, port of `legacy:aiops/security/ttl.py`). The owned analytical store
keeps a row for one of exactly two lengths of time and nothing else in this repository may restate
them: `schema.py` renders its ``TTL`` clause **from** this module, so a declared table cannot be
built with a retention the policy does not say, and `store.py` reads a live table's
``create_table_query`` back through `parse_ttl_expression` so declared-versus-deployed drift is a
testable fact rather than a paragraph in a runbook.

**Security-event retention is separate from telemetry retention.** SigNoz stores
traces, metrics and logs under per-signal policies configured through
`components/data/store-signoz/retention.py` and compared by
`local_observe/store/retention.py`. This module governs rows in an independently
owned security table. Applying a short telemetry policy to that table would discard
security records before their declared retention period.

Why a separate mechanism exists at all (A-5, and the reason v0.1 built the store): SigNoz retention
is **per signal** — one TTL for all of ``signoz_logs`` — so it cannot hold one row for five years
and its neighbour for ninety days, and its upgrade migrations rewrite its managed tables, so a
hand-ALTER inside ``signoz_*`` is a claim until the next upgrade. A tier over a security record is
therefore declared on an owned table and never borrowed from a signal.

Stdlib only, pure except for the day arithmetic in `deadline`.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass

# A-5's band, at its long end: `critical` rows are kept five years. `routine` rows are kept far
# below them, past the horizon a human triage or a parsed alert still needs but short enough that a
# wrong verdict about "sensitive" does not sit in a five-year table.
CRITICAL_TTL_DAYS = 1825
ROUTINE_TTL_DAYS = 90

# The stable retention status label is checked by the conformance tests. It is the one
# sentence in this package that exists purely to stop a reader merging two retention lists: this
# module's numbers are a per-row security tier on an owned table, telemetry retention's are a per-signal SigNoz
# setting, and the two are read, written and reported by different code.
RETENTION_CONTRAST_WITH_D9 = ("Security-event retention is separate from telemetry retention for "
                              "traces, metrics and logs. Per-signal policies are compared by "
                              "local_observe/store/retention.py; they must not override security tiers.")

# The two tiers, spelled once. The column is named `retention_tier` and NOT `data_class` on purpose:
# `data_class` is already a canonical-event field with a closed vocabulary of its own —
# `public` / `internal` / `restricted`, enforced by `state.validate_event` — and every event this
# store holds says `internal` there (see `platform/detections.event`). A second, different
# `data_class` in the same product would be read as the first one by everyone, including the code
# that has to compare them.
TIER_CRITICAL = 'critical'
TIER_ROUTINE = 'routine'
TIERS = (TIER_CRITICAL, TIER_ROUTINE)

# Which tier one canonical event lands on. Loudness is the only signal this store has: the event
# vocabulary carries no "this is the sensitive one" field, and severity is already the crosswalk's
# answer (`platform/vocabulary.py`). It is a mapping and not a judgement, so it lives next to the
# numbers it selects between. What it means today: `sigma_runner` files a finding at `warning`
# through `detections.event`, so every Sigma row is `routine` and the five-year tier stays empty
# until a producer files `critical` (see docs/CONTRACTS.md §4.3).
TIER_BY_SEVERITY = {'critical': TIER_CRITICAL, 'warning': TIER_ROUTINE, 'info': TIER_ROUTINE}

# How often a running producer re-reads the live table's TTL. The check is cheap (one aggregate
# `SELECT` on `system.tables`) but it is not free, and a policy nobody changed in an hour will not
# disagree in the next minute. It is a floor in code, not a knob: see `TtlComparison` for what the
# answer costs when it is wrong.
TTL_CHECK_INTERVAL_SECONDS = 3600

# The closed verdict vocabulary of `compare`. `no-ttl` is a status and not a zero because "the table
# has no TTL" and "the table keeps rows for 0 days" are different claims about the same shelf — the
# first is a table that grows forever, the second has already deleted everything.
COMPARISON_STATUSES = ('match', 'drift', 'no-ttl', 'unreadable')


class TtlRefused(ValueError):
    """A TTL policy or expression this module will not read; the reason names the rule, never a value."""


@dataclass(frozen=True)
class RetentionPolicy:
    """The two-tier retention every security-event table is built with and checked against.

    Whole days only: ClickHouse renders both spellings it accepts (`INTERVAL n DAY` in the DDL,
    `toIntervalDay(n)` in `system.tables.create_table_query`) in days, and a policy in hours would be
    parsed back into days by `parse_ttl_expression` — so an hour-level tier could never be confirmed
    against a live table and would read as drift forever.
    """

    critical_days: int = CRITICAL_TTL_DAYS
    routine_days: int = ROUTINE_TTL_DAYS

    def __post_init__(self) -> None:
        """Refuse an impossible policy before it is rendered into DDL.

        The ordering invariant is load-bearing and not tidiness: the ``critical`` tier is the long
        one, so a policy that keeps routine rows longer than critical ones retains *more* of the
        ordinary records than of the ones somebody called worth keeping for years.
        """
        for name, days in ((TIER_CRITICAL, self.critical_days), (TIER_ROUTINE, self.routine_days)):
            if isinstance(days, bool) or not isinstance(days, int) or days < 1:
                raise TtlRefused(f'{name} retention must be a whole number of days of at least 1')
        if self.critical_days < self.routine_days:
            raise TtlRefused(f'critical ({self.critical_days}d) must outlive routine ({self.routine_days}d); '
                             f'a policy that keeps routine rows longer retains more of the ordinary data '
                             f'than of the rows somebody said to keep')

    def days(self, tier: str) -> int:
        """Return how many days one *tier* is kept; an unknown tier is a refusal."""
        if tier == TIER_CRITICAL:
            return self.critical_days
        if tier == TIER_ROUTINE:
            return self.routine_days
        raise TtlRefused(f'unknown retention tier {tier!r}; this store keeps {", ".join(TIERS)}')

    def as_dict(self) -> dict[str, int]:
        """Return the policy as ``{tier: days}``, the form a report or a log line carries."""
        return {TIER_CRITICAL: self.critical_days, TIER_ROUTINE: self.routine_days}


DEFAULT_POLICY = RetentionPolicy()


def tier_for(severity: str) -> str:
    """Return the tier one canonical event's *severity* selects; an unknown word is a refusal.

    Refusing rather than defaulting to `routine` is the whole point: a default would silently send a
    row a producer meant to be kept for years into the 90-day tier, which is a retention decision
    nobody made. `state.validate_event` admits three severities, so `TIER_BY_SEVERITY` covers all of
    them and anything else is a bug in the caller.
    """
    try:
        return TIER_BY_SEVERITY[severity]
    except KeyError:
        raise TtlRefused(f'no retention tier for severity {severity!r}; this store tiers on '
                         f'{", ".join(sorted(TIER_BY_SEVERITY))}') from None


def build_ttl_clause(policy: RetentionPolicy = DEFAULT_POLICY) -> str:
    """Return the ``TTL`` clause (leading keyword included) that *policy* requires.

    One clause with two conditions, because that is what the store exists to have: both tiers live
    in one table and ClickHouse deletes a row when the condition whose ``WHERE`` matches it reaches
    its own deadline. `schema.py` pastes this text into its ``CREATE TABLE`` verbatim, so the table
    and the policy are the same number written twice rather than two numbers kept in step.
    """
    conditions = ', '.join(
        f"toDateTime(ts) + INTERVAL {policy.days(tier)} DAY DELETE WHERE retention_tier = '{tier}'"
        for tier in TIERS)
    return f'TTL {conditions}'


def deadline(tier: str, instant: dt.datetime, policy: RetentionPolicy = DEFAULT_POLICY) -> dt.datetime:
    """Return the instant a row stamped *instant* becomes deletable under *tier*.

    Whole days added in UTC, so the answer does not depend on the host's zone — the same reason the
    DDL stamps its column ``DateTime64(9, 'UTC')``. ClickHouse applies the delete lazily (on the
    next part merge), so this is the deadline from which a row is *due*, not the moment it is gone.
    """
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise TtlRefused('A TTL deadline needs a timezone-aware datetime')
    return instant.astimezone(dt.timezone.utc) + dt.timedelta(days=policy.days(tier))


MAX_DDL_BYTES = 65536
MAX_TTL_BYTES = 8192
MAX_SQL_DEPTH = 64
_WORD = re.compile(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+')


def _sql_tokens(text: str, maximum: int) -> list[tuple[str, str]]:
    """Tokenize bounded metadata, preserving quoted values and refusing broken structure."""
    if not isinstance(text, str):
        raise TtlRefused('The table metadata must be text')
    try:
        oversized = len(text) > maximum or len(text.encode('utf-8')) > maximum
    except UnicodeError:
        raise TtlRefused('The table metadata is not valid Unicode') from None
    if oversized:
        raise TtlRefused('The table metadata exceeds its byte limit')
    tokens: list[tuple[str, str]] = []
    index, depth = 0, 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if text.startswith('--', index) or char == '#':
            end = text.find('\n', index + 1)
            index = len(text) if end < 0 else end + 1
            continue
        if text.startswith('/*', index):
            end = text.find('*/', index + 2)
            if end < 0 or '/*' in text[index + 2:end]:
                raise TtlRefused('The table metadata has a malformed comment')
            index = end + 2
            continue
        if char in "'\"`":
            quote, start = char, index
            index += 1
            while index < len(text):
                if text[index] == '\\':
                    index += 2
                elif text[index] == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise TtlRefused('The table metadata has an unterminated quote')
            tokens.append(('string' if quote == "'" else 'quoted', text[start:index]))
            continue
        word = _WORD.match(text, index)
        if word:
            value = word.group()
            tokens.append(('number' if value.isdigit() else 'word', value))
            index = word.end()
            continue
        if char == '(':
            depth += 1
            if depth > MAX_SQL_DEPTH:
                raise TtlRefused('The table metadata exceeds its nesting limit')
        elif char == ')':
            depth -= 1
            if depth < 0:
                raise TtlRefused('The table metadata has unbalanced parentheses')
        elif ord(char) < 32 or ord(char) == 127:
            raise TtlRefused('The table metadata holds a control character')
        tokens.append(('symbol', char))
        index += 1
    if depth:
        raise TtlRefused('The table metadata has unbalanced parentheses')
    return tokens


def _top_level(tokens: list[tuple[str, str]], value: str) -> list[int]:
    """Locate unquoted tokens outside parentheses."""
    depth, found = 0, []
    for index, (kind, text) in enumerate(tokens):
        if kind in ('word', 'symbol') and not depth and text.upper() == value:
            found.append(index)
        if (kind, text) == ('symbol', '('):
            depth += 1
        elif (kind, text) == ('symbol', ')'):
            depth -= 1
    return found


def table_ttl_expression(statement: str) -> str:
    """Extract only the table TTL from supported ``system.tables.create_table_query`` metadata."""
    tokens = _sql_tokens(statement, MAX_DDL_BYTES)
    if tokens and tokens[-1] == ('symbol', ';'):
        tokens.pop()
    engines, bodies = _top_level(tokens, 'ENGINE'), _top_level(tokens, '(')
    if (len(tokens) < 3 or [(kind, text.upper()) for kind, text in tokens[:2]]
            != [('word', 'CREATE'), ('word', 'TABLE')]
            or ('symbol', ';') in tokens or len(engines) != 1 or not bodies
            or not 2 < bodies[0] < engines[0]
            or tokens[engines[0] - 1] != ('symbol', ')')
            or tokens[engines[0] + 1:engines[0] + 2] != [('symbol', '=')]):
        raise TtlRefused('The table metadata is not a supported CREATE TABLE statement')
    endings = _top_level(tokens, 'SETTINGS') + _top_level(tokens, 'COMMENT')
    end = min(endings, default=len(tokens))
    starts = _top_level(tokens[:end], 'TTL')
    if not starts:
        return ''
    if len(starts) != 1 or starts[0] < engines[0] or starts[0] + 1 == end:
        raise TtlRefused('The table metadata has an invalid table TTL clause')
    expression = ' '.join(text for _, text in tokens[starts[0] + 1:end])
    if len(expression.encode('utf-8')) > MAX_TTL_BYTES:
        raise TtlRefused('The table TTL exceeds its byte limit')
    return expression


def _unwrapped(tokens: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Remove parentheses only when they enclose the complete expression."""
    while tokens and tokens[0] == ('symbol', '('):
        depth = 0
        for index, token in enumerate(tokens):
            if token == ('symbol', '('):
                depth += 1
            elif token == ('symbol', ')'):
                depth -= 1
            if not depth:
                if index != len(tokens) - 1:
                    return tokens
                break
        tokens = tokens[1:-1]
    return tokens


def _identifier(token: tuple[str, str], name: str) -> bool:
    """Match an owned, case-sensitive column name with optional identifier quoting."""
    return token == ('word', name) or token in (('quoted', f'`{name}`'), ('quoted', f'"{name}"'))


def _tier_clause(tokens: list[tuple[str, str]]) -> tuple[str, int]:
    """Accept guarded day deletion, including SHOW CREATE's implicit DELETE form."""
    guards = _top_level(tokens, 'WHERE')
    if len(guards) != 1:
        raise TtlRefused('The live table TTL must contain only guarded day deletions')
    split = guards[0]
    expiry = tokens[:split]
    # ClickHouse 25.12 SHOW CREATE omits DELETE for the default deletion action.
    # Only that single optional keyword is consumed; MOVE/RECOMPRESS/GROUP BY and
    # extra DELETE tokens remain in expiry and fail its exact arithmetic grammar.
    if expiry and (expiry[-1][0], expiry[-1][1].upper()) == ('word', 'DELETE'):
        expiry = expiry[:-1]
    expiry, guard = _unwrapped(expiry), tokens[split:]
    guard = _unwrapped(guard[1:])
    if (len(guard) != 3 or not _identifier(guard[0], 'retention_tier')
            or guard[1] != ('symbol', '=') or guard[2] not in [('string', f"'{tier}'") for tier in TIERS]):
        raise TtlRefused('The live table TTL has an unsupported retention guard')
    plus = _top_level(expiry, '+')
    if len(plus) != 1:
        raise TtlRefused('The live table TTL must expire relative to the event timestamp')
    stamp, interval = _unwrapped(expiry[:plus[0]]), _unwrapped(expiry[plus[0] + 1:])
    if (len(stamp) < 4 or (stamp[0][0], stamp[0][1].lower()) != ('word', 'todatetime')
            or stamp[1] != ('symbol', '(') or stamp[-1] != ('symbol', ')')):
        raise TtlRefused('The live table TTL must expire relative to the event timestamp')
    argument = _unwrapped(stamp[2:-1])
    if len(argument) != 1 or not _identifier(argument[0], 'ts'):
        raise TtlRefused('The live table TTL must expire relative to the event timestamp')
    normalized = [(kind, text.upper() if kind == 'word' else text) for kind, text in interval]
    if (len(normalized) == 4 and normalized[0] == ('word', 'TOINTERVALDAY')
            and normalized[1] == ('symbol', '(') and normalized[3] == ('symbol', ')')):
        number = normalized[2]
    elif (len(normalized) == 3 and normalized[0] == ('word', 'INTERVAL')
          and normalized[2] == ('word', 'DAY')):
        number = normalized[1]
    else:
        raise TtlRefused('The live table TTL must use a whole-day interval')
    if number[0] != 'number' or len(number[1]) > 10:
        raise TtlRefused('The live table TTL has an invalid day count')
    return guard[2][1][1:-1], int(number[1])


def parse_ttl_expression(expression: str) -> RetentionPolicy | None:
    """Parse the extracted table TTL into the exact two-tier policy.

    An empty extracted clause means the existing table has no TTL and returns ``None``. Other
    expressions must contain both guarded deletions and nothing else; unfamiliar expressions
    refuse rather than report agreement.
    """
    tokens = _sql_tokens(expression, MAX_TTL_BYTES)
    if not tokens:
        return None
    found: dict[str, int] = {}
    boundaries = [-1, *_top_level(tokens, ','), len(tokens)]
    for start, end in zip(boundaries, boundaries[1:]):
        tier, days = _tier_clause(tokens[start + 1:end])
        if tier in found:
            raise TtlRefused(f'the live table declares tier {tier!r} twice in one TTL clause')
        found[tier] = days
    missing = [tier for tier in TIERS if tier not in found]
    if missing:
        raise TtlRefused(f'the live table TTL exposes no {", ".join(missing)} condition, so a declared '
                         f'tier is not deployed on it')
    return RetentionPolicy(critical_days=found[TIER_CRITICAL], routine_days=found[TIER_ROUTINE])


@dataclass(frozen=True)
class TtlComparison:
    """What the live table's TTL says, next to what this module declares.

    ``status`` is one of `COMPARISON_STATUSES` and is the word a report or a coverage event repeats;
    ``detail`` is the same claim in one sentence with both numbers in it, because a reader who is
    told ``drift`` without the two day counts has been told that something is wrong and nothing about
    what. A ``live`` of ``None`` is the `no-ttl` case, not a zero-day policy.
    """

    status: str
    declared: RetentionPolicy
    live: RetentionPolicy | None
    detail: str

    def __post_init__(self) -> None:
        """Refuse a verdict word outside the closed set, so a coverage event cannot invent one."""
        if self.status not in COMPARISON_STATUSES:
            raise TtlRefused(f'unknown TTL verdict {self.status!r}; this check answers '
                             f'{", ".join(COMPARISON_STATUSES)}')

    @property
    def matches(self) -> bool:
        """True only when the live table carries exactly the declared two tiers."""
        return self.status == 'match'

    def as_dict(self) -> dict[str, object]:
        """Return the verdict as JSON-safe text for a log line or a portal field."""
        return {'status': self.status,
                'declared': self.declared.as_dict(),
                'live': self.live.as_dict() if self.live is not None else None,
                'detail': self.detail}


def _reading(days: int | None) -> str:
    """Render one tier length the way the policy states it, with ``None`` kept distinct."""
    return 'no TTL' if days is None else f'{days}d'


def compare(expression: str, policy: RetentionPolicy = DEFAULT_POLICY) -> TtlComparison:
    """Judge an extracted table TTL against *policy* — the drift check itself.

    Four answers and no exceptions, because this runs on a schedule and a raised exception is the
    same visible nothing as a dropped check:

    * ``match`` — both tiers, both numbers equal;
    * ``drift`` — both tiers present, at least one number different (the hand-ALTER case, or a policy
      change that was merged but never applied to the table);
    * ``no-ttl`` — the table exists with no TTL at all, so nothing is ever deleted and the store grows
      forever;
    * ``unreadable`` — a TTL string that does not expose exactly the two declared tiers, or a table
      this reader cannot describe. This is the case where an operator's edit has left the table in a
      shape the product has no word for, which must not be reported as health.
    """
    try:
        live = parse_ttl_expression(expression)
    except TtlRefused as exc:
        return TtlComparison(status='unreadable', declared=policy, live=None, detail=str(exc))
    if live is None:
        return TtlComparison(status='no-ttl', declared=policy, live=None,
                             detail=f'the live table carries no TTL clause at all, so nothing is expiring; '
                                    f'declared {_reading(policy.critical_days)} on {TIER_CRITICAL} and '
                                    f'{_reading(policy.routine_days)} on {TIER_ROUTINE}')
    if live == policy:
        return TtlComparison(status='match', declared=policy, live=live,
                             detail=f'live TTL is {_reading(live.critical_days)}/{_reading(live.routine_days)} '
                                    f'on {TIER_CRITICAL}/{TIER_ROUTINE}, as declared')
    lines = [f'{tier}: declared {_reading(policy.days(tier))} but the live table keeps '
             f'{_reading(live.days(tier))}' for tier in TIERS if policy.days(tier) != live.days(tier)]
    return TtlComparison(status='drift', declared=policy, live=live, detail='; '.join(lines))
