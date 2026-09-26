"""One gate against the defect the verification admission had to fix by hand: two rows in `DEPENDENCIES.md` for one change.

The map is a two-column Markdown table keyed on its first column. Nothing in the suite read it, so the
map carried **two** rows titled `Consistent copy of another service's state` with different content (the
busctl retirement scripts row landed beside the pre-job observe standard copy it superseded) and no check could tell a
reviewer which line
had gone stale. The verification admission reconciled them by deleting one; the audit throttling filed this gate so
the same shape
needs a human eye to catch.

Two rules are claimed here, both about where a row starts and stops and neither about its content. The
first is the key: it is read up to the *first* closing pipe and the rest of the line is kept whole,
because a description cell may legitimately contain pipes (inline code is where they arrive — measured
2026-09-10, two of the map's 91 rows carry them, one as a `grep` alternation and one as a `toJson`
template) and splitting the row would turn each one into a phantom key. The second, added by map guard and artifact
cap, is
that a row which opens and never closes is a **refusal** rather than prose. What is still deliberately
**not** here: a Markdown parser, a front-matter reader, a renderer, cell-count validation or any
structural claim about the description column.

The second rule exists because the first one was silently blind. events incident index found the map's RCA row had lost
its closing pipe and had therefore been read as prose since the day it was written — the duplicate-key
guard never saw it (89 rows parsed before the pipe was restored, 91 after,
`docs/evidence/2026-09-10-claude-wave8.md`). A guard that skips the row it cannot parse is not a guard,
so `map_rows` now raises on that shape: a stripped line beginning with `|`, holding a second `|` after
it and not ending with one. A leading `|` with no second pipe stays prose, because that is a stray
character and not an attempt at a row.

The checked-out map is located from `__file__`, never from the working directory, and an empty or
table-less file **refuses** rather than reporting "no duplicates": a guard that passes on a file it
failed to read would guard nothing. Offline, stdlib only, no product import — a test that reports on a
document must not depend on the code that document describes.
"""
from pathlib import Path
import os
import tempfile
import unittest
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCY_MAP = ROOT / 'DEPENDENCIES.md'

# Rows that have been in the map since it was written. If a run cannot find them it is not reading the
# map (wrong root, empty file, a parser that matched nothing) rather than the map being clean.
REAL_MAP_KEYS = ('Component image build inputs', 'Deterministic CI')
# 91 data rows measured 2026-09-10 by this file's own parser (46 measured 2026-09-08). The floor stays
# well below the measurement on purpose: sibling worktrees add rows, and a floor that moves with the
# count turns a legitimate new row into this file's failure.
REAL_MAP_MIN_ROWS = 40
# How much of an unterminated row the refusal quotes back. The longest map row on this checkout is
# 4,058 characters, so quoting one whole would bury the line number the reader has to act on.
ROW_EXCERPT_MAX = 80


class MapRow(NamedTuple):
    """One data row of the map: its 1-based line number, its first-column key, its description cell."""

    number: int
    key: str
    description: str


def _is_row(line: str) -> bool:
    """True when this line is a table row — a cell run between a leading and a trailing pipe on one line.

    Prose and blank lines answer False, which is what keeps the paragraphs above and below the table out
    of the key set. A row whose closing pipe was lost also answers False, but it is **not** skipped: the
    caller refuses it (see `_unterminated_row`). Until map guard and artifact cap that False was how a real row
    disappeared
    from this guard's view of the map.
    """
    body = line.strip()
    return len(body) > 2 and body.startswith('|') and body.endswith('|')


def _unterminated_row(line: str) -> bool:
    """True when this line opens a table row and never closes it — the shape map guard and artifact cap refuses.

    Three conditions on the stripped line: it starts with a pipe, it carries a second pipe after that
    one, and it does not end with a pipe. The second pipe is the whole distinction — `| note written in
    prose` is a stray character, while `| RCA | a row whose tail is gone` is a row with an opening and a
    body. Nothing here tries to tell a broken row from prose that happens to hold two pipes: the point of
    the guard is to stop silently choosing between them, and a map that ever needs such prose grows that
    rule deliberately, in the open, rather than losing a row again.
    """
    body = line.strip()
    return body.startswith('|') and not body.endswith('|') and '|' in body[1:]


def _refuse_unterminated(lines: list[str], source: str | None) -> None:
    """Raise on the first unterminated row in ``lines``, naming the map, the line and a quote of the row.

    The first in file order is the one a reader meets first, so only that one is quoted; the count comes
    along when there is more than one, which saves a fix-and-rerun cycle without pasting every broken row
    into the failure. ``source`` is the path the text came from when one exists (`read_map_rows` always
    passes it); a bare `map_rows` call on a fixture reports the line number alone.
    """
    numbers = [number for number, line in enumerate(lines, 1) if _unterminated_row(line)]
    if not numbers:
        return
    first = numbers[0]
    where = f'{source}: ' if source else ''
    rest = '' if len(numbers) == 1 else f' (the first of {len(numbers)} such lines)'
    raise AssertionError(
        f'{where}unterminated dependency-map row on line {first}{rest}: a table row must end with "|". '
        f'Found {lines[first - 1].strip()[:ROW_EXCERPT_MAX]!r}')


def _is_separator(line: str) -> bool:
    """True for the `|---|---|` rule that sits under a Markdown table header."""
    body = line.strip()
    return _is_row(body) and '-' in body and set(body) <= set('|-: \t')


def map_rows(text: str, source: str | None = None) -> list[MapRow]:
    """Return the data rows of every table in ``text``, with the header and rule of each dropped.

    Three exclusions decide what is a row: a line that is not a row (prose, blank), the rule line
    itself, and the row sitting directly above the rule (the header, so `Change` is never a key). The key
    is whatever stands between the first pipe and the next one — `partition`, not `split` — because a
    description cell may legitimately hold pipes inside inline code.

    A first cell that itself contained a pipe would be read up to that pipe (none does on this
    checkout, measured); escaping is not guessed here, so a map that ever needs it must grow that rule
    deliberately rather than get a silent truncation. Rows come back in file order with their real line
    numbers, and nothing here decides which of two same-keyed rows is the stale one — that judgement
    stays with the reader of the failure.

    Raises:
        AssertionError: when the text holds an unterminated row (see `_refuse_unterminated`), naming
            ``source`` when given, that line's 1-based number and the first `ROW_EXCERPT_MAX`
            characters of it. The refusal happens before any row is returned.
    """
    lines = text.splitlines()
    _refuse_unterminated(lines, source)
    rows = []
    for index, line in enumerate(lines):
        if not _is_row(line) or _is_separator(line):
            continue
        if index + 1 < len(lines) and _is_separator(lines[index + 1]):
            continue
        key, _, tail = line.strip()[1:].partition('|')
        rows.append(MapRow(index + 1, key.strip(), tail.strip().removesuffix('|').strip()))
    return rows


def read_map_rows(path: Path = DEPENDENCY_MAP) -> list[MapRow]:
    """Rows of the map at ``path``, refusing a file that yields no table row or holds an unterminated row.

    A missing file raises `FileNotFoundError`; an empty, prose-only or malformed table raises
    `AssertionError` naming the path and the byte count, and a row that lost its closing pipe raises
    `AssertionError` naming the path and that row's line number (both from `map_rows`, which is handed
    the path as its `source`). "The map is clean" can therefore only ever come from a map that was read
    whole.
    """
    raw = path.read_bytes()
    rows = map_rows(raw.decode('utf-8'), source=str(path))
    if not rows:
        raise AssertionError(f'{path}: no dependency-map table rows found in {len(raw)} bytes')
    return rows


def duplicate_keys(rows: list[MapRow]) -> dict[str, list[int]]:
    """{key: [line numbers]} for each **nonempty** first-column key used by more than one row.

    An empty first cell is not a key, so two placeholder rows are not the defect guarded here. The
    result keeps first-appearance order, which makes the diagnostic read top-down through the map.
    """
    seen: dict[str, list[int]] = {}
    for row in rows:
        if row.key:
            seen.setdefault(row.key, []).append(row.number)
    return {key: numbers for key, numbers in seen.items() if len(numbers) > 1}


def duplicate_report(rows: list[MapRow], source: str) -> str:
    """One line per repeated key — empty string when the map is clean — naming the key and its lines.

    The key is quoted and every occurrence numbered because the fix is "delete the stale row": a
    reader must not have to open the map to find which line is which.
    """
    return ''.join(
        f'{source}: duplicate dependency-map key {key!r} on lines '
        f'{" and ".join(str(number) for number in numbers)}\n'
        for key, numbers in duplicate_keys(rows).items())


# Header, rule, prose and pipes inside the description cell — all of which must NOT become keys, and
# none of which may hide the real key of the row that carries them.
CLEAN_FIXTURE = '\n'.join((
    '# Product dependency map',
    '',
    'Prose naming no row at all.',
    '| Change | Dependent updates and checks |',
    '|---|---|',
    '| Alpha | paths, `pipe | separated` inline code, more paths |',
    '| Beta | one path |',
    '',
    'Trailing prose holding `|a | b|`, which is not a row and names no key.',
))

# The the verification admission shape: the same key twice, with descriptions that differ, so nothing else about the
# two rows proves they are duplicates to a reader skimming the file.
DUPLICATE_FIXTURE = '\n'.join((
    '| Change | Dependent updates and checks |',
    '|---|---|',
    "| Consistent copy of another service's state | current row: writer exclusion, live callers named |",
    '| Notification policy or delivery | notification_safety.py |',
    "| Consistent copy of another service's state | stale row: pre-job observe standard wording, no callers |",
))

PLACEHOLDER_FIXTURE = '\n'.join((
    '| Change | Dependent updates and checks |',
    '|---|---|',
    '| | a row whose key cell is empty |',
    '| Real key | a row with a key |',
    '| | a second row whose key cell is empty |',
))

# map guard and artifact cap's shape: the data row on line 6 lost its closing pipe. Read as prose it vanishes from the
# key
# set entirely — which is how the map carried its RCA row outside this guard from the day that row was
# written (89 rows parsed, 91 once events incident index restored the pipe).
UNTERMINATED_ROW = '| RCA | root-cause analysis rows, `rca.py`, `rca_cli.py` and their tests'
_FIXTURE_LINES = ('# Product dependency map', '', '| Change | Dependent updates and checks |', '|---|---|',
                  '| Alpha | first row |', UNTERMINATED_ROW, '| Beta | last row |')
UNTERMINATED_FIXTURE = '\n'.join(_FIXTURE_LINES)
# The same text with the one character put back, so the refusal below cannot be a fixture artefact.
RESTORED_FIXTURE = '\n'.join(_FIXTURE_LINES[:5] + (UNTERMINATED_ROW + ' |',) + _FIXTURE_LINES[6:])

# A line that opens with a pipe and holds no second one stays prose: a stray character, not a row. The
# new refusal must not swallow the map's opening or closing paragraphs, which are what this shape
# stands for.
STRAY_PIPE_FIXTURE = '\n'.join((
    '| Change | Dependent updates and checks |',
    '|---|---|',
    '| Alpha | a row |',
    '',
    '| a stray pipe opening a prose line, which names no key',
    'Trailing prose holding `|a | b|`, which is not a row and names no key.',
))


class RealMapTests(unittest.TestCase):
    """The gate as it ships: the checked-out map must hold exactly one row per key."""

    def test_the_checked_out_map_uses_each_key_once(self):
        rows = read_map_rows()
        report = duplicate_report(rows, DEPENDENCY_MAP.name)
        self.assertEqual(report, '', report)

    def test_the_checked_out_map_is_actually_parsed(self):
        """Anti-vacuous control for the test above: rows, known keys and no empty key to hide in."""
        rows = read_map_rows()
        self.assertGreaterEqual(len(rows), REAL_MAP_MIN_ROWS)
        keys = {row.key for row in rows}
        for expected in REAL_MAP_KEYS:
            self.assertIn(expected, keys)
        self.assertEqual([row.number for row in rows if not row.key], [])

    def test_the_map_is_located_from_the_checkout_and_not_the_working_directory(self):
        from_checkout = [tuple(row) for row in read_map_rows()]
        self.assertTrue(DEPENDENCY_MAP.is_absolute())
        self.assertEqual(DEPENDENCY_MAP.parent, ROOT)
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                moved = [tuple(row) for row in read_map_rows()]
            finally:
                os.chdir(previous)
        self.assertEqual(moved, from_checkout)

    def test_the_checked_out_map_holds_no_unterminated_row(self):
        """Positive control for the refusal below: the shipped map must satisfy the rule, not just the fixture.

        A guard that fires on its own fixture and never on the file is the same silent skip with extra
        steps, so the real file is read twice — once through `read_map_rows` (which now refuses an
        unterminated row) and once by counting such lines directly, so a row that lost its pipe names its
        line number instead of only shrinking the row count. 91 rows parse on 2026-09-10.
        """
        text = DEPENDENCY_MAP.read_text(encoding='utf-8')
        broken = [number for number, line in enumerate(text.splitlines(), 1) if _unterminated_row(line)]
        self.assertEqual(broken, [], f'DEPENDENCIES.md: unterminated rows on lines {broken}')
        self.assertGreaterEqual(len(read_map_rows(DEPENDENCY_MAP)), REAL_MAP_MIN_ROWS)


class MapHelperTests(unittest.TestCase):
    """The helper's own contract, on fixtures, so a change to it cannot silently move the gate."""

    def test_header_rule_prose_and_pipes_in_the_description_are_not_keys(self):
        rows = map_rows(CLEAN_FIXTURE)
        self.assertEqual([row.key for row in rows], ['Alpha', 'Beta'])
        self.assertEqual([row.number for row in rows], [6, 7])
        self.assertEqual(rows[0].description, 'paths, `pipe | separated` inline code, more paths')
        self.assertEqual(duplicate_report(rows, 'fixture'), '')

    def test_a_repeated_key_is_reported_by_name_even_when_the_two_rows_differ(self):
        rows = map_rows(DUPLICATE_FIXTURE)
        self.assertEqual([row.key for row in rows].count(
            "Consistent copy of another service's state"), 2)
        first, second = (row for row in rows if row.key.startswith('Consistent'))
        self.assertNotEqual(first.description, second.description)
        report = duplicate_report(rows, 'DEPENDENCIES.md')
        self.assertEqual(len(report.splitlines()), 1)
        self.assertIn("Consistent copy of another service's state", report)
        self.assertIn('lines 3 and 5', report)

    def test_an_empty_first_cell_is_not_a_key(self):
        rows = map_rows(PLACEHOLDER_FIXTURE)
        self.assertEqual([row.key for row in rows], ['', 'Real key', ''])
        self.assertEqual(duplicate_keys(rows), {})
        self.assertEqual(duplicate_report(rows, 'fixture'), '')

    def test_a_row_that_lost_its_closing_pipe_refuses_and_names_its_line(self):
        """map guard and artifact cap: skipping the row this guard exists to read is the defect, so that shape must be a refusal.

        Both halves are asserted: the broken text raises with the line number a reader can act on, and
        the identical text with the pipe restored parses all three rows in file order. Without the
        second half this test would only prove the guard is loud.
        """
        with self.assertRaises(AssertionError) as context:
            map_rows(UNTERMINATED_FIXTURE)
        message = str(context.exception)
        self.assertIn('unterminated dependency-map row on line 6', message)
        self.assertIn('rca.py', message, 'the refusal quotes the broken row, so it is recognisable')
        self.assertNotIn('Beta', message, 'and quotes that row alone, not the rows beside it')
        rows = map_rows(RESTORED_FIXTURE)
        self.assertEqual([row.key for row in rows], ['Alpha', 'RCA', 'Beta'])
        self.assertEqual([row.number for row in rows], [5, 6, 7])

    def test_a_file_holding_only_an_unterminated_row_refuses_rather_than_reading_as_empty(self):
        """A file whose only row is broken must be refused as a broken row, not reported as an empty table.

        Read through `read_map_rows`, because that is where the two refusals meet: had the unterminated
        row still been skipped, this file would have looked table-less and said so, which is a wrong
        diagnosis of a broken pipe rather than the right one.
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'DEPENDENCIES.md'
            path.write_text('| Change | Cell |\n|---|---|\n| Key | value\n', encoding='utf-8')
            with self.assertRaises(AssertionError) as context:
                read_map_rows(path)
        message = str(context.exception)
        self.assertIn('unterminated dependency-map row on line 3', message)
        self.assertIn(path.name, message, 'a refusal from a file names the file it read')
        self.assertNotIn('no dependency-map table rows found', message)

    def test_the_quoted_row_is_bounded_to_the_stated_number_of_characters(self):
        """A map row here runs to 4,058 characters, so the diagnostic quotes a prefix and says so."""
        long_row = '| Kilo | ' + 'y' * (ROW_EXCERPT_MAX * 3)
        with self.assertRaises(AssertionError) as context:
            map_rows('\n'.join(('| Change | Cell |', '|---|---|', long_row)))
        message = str(context.exception)
        self.assertIn('on line 3', message)
        quoted = message.split('Found ', 1)[1]
        self.assertEqual(quoted[1:-1], long_row[:ROW_EXCERPT_MAX],
                         'the quote is the row prefix inside repr quotes')
        self.assertEqual(len(quoted), ROW_EXCERPT_MAX + 2, 'two of those characters are the quotes')
        self.assertLess(ROW_EXCERPT_MAX, len(long_row), 'and the row really was longer than the quote')

    def test_a_leading_pipe_holding_no_second_pipe_stays_prose(self):
        """The narrow half of the new rule: `| prose` is a stray character and must not trip the refusal."""
        rows = map_rows(STRAY_PIPE_FIXTURE)
        self.assertEqual([row.key for row in rows], ['Alpha'])
        self.assertEqual([row.number for row in rows], [3])
        self.assertEqual(duplicate_report(rows, 'fixture'), '')

    def test_an_empty_or_tableless_map_refuses_instead_of_passing(self):
        self.assertEqual(map_rows(''), [])
        self.assertEqual(map_rows('# Heading\n\nprose, no pipe\n'), [])
        # A row that lost its closing pipe is a refusal now, not an empty map: "nothing parseable" and
        # "something unreadable" stay different answers (the second half lives in the test above).
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / 'DEPENDENCIES.md'
            empty.write_text('', encoding='utf-8')
            prose = root / 'prose.md'
            prose.write_text('No table here at all.\n', encoding='utf-8')
            for path in (empty, prose):
                with self.assertRaises(AssertionError) as context:
                    read_map_rows(path)
                self.assertIn(path.name, str(context.exception))
            with self.assertRaises(FileNotFoundError):
                read_map_rows(root / 'missing.md')


if __name__ == '__main__':
    unittest.main()
