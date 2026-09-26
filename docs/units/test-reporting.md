# Unit: test reporting (`tests/tiers.py`)

**File(s):** `tests/tiers.py` (a tool, not a test module — the name keeps it out of discovery) ·
**Tests:** `tests/test_tiers.py`, `tests/test_tiers_single_pass.py`, `tests/test_ci_single_pass.py` · **Consumers:** `.gitea/workflows/ci.yml` (all three tiers),
`docs/testing-standards.md` · **Config:** none — command line only, no environment variable and no
product import.

> The dependency import boundary. The change is that a tier is now **run once**: the reporter executes the suite, so the
> measured base tier wraps *this* command in `coverage run` instead of running
> `coverage run -m unittest discover -s tests` and then the reporter over the same directory again.
> The report schema did not change (`schema_version` is still 1) and every field the old artifact had
> is still there, with the same shape.

## Purpose

Say, in an artifact CI keeps, which tests ran, which skipped, on which gate, and which never loaded —
per start directory, in the interpreter that ran them. No single machine or environment runs this
repository's whole suite, so "the suite is green" is only meaningful as the union of three reports
joined by test id. A skip printed to a human and forgotten is not evidence; a skip with its id, its
decorator's own reason and the host that produced it is.

The tool must not depend on the code it reports on: it imports nothing from `local_observe`, and it
uses the standard library only.

## Command line

```
python -B tests/tiers.py [--start-dir DIR ...] [--json PATH] [--only-tier TIER] [--quiet | --verbose]
```

* `--start-dir` (repeatable, default `tests`) — one tier each, discovered and executed exactly once,
  in the order given. The same process may serve two directories (`tests` and `tests/compiler`) when
  one interpreter can run both; CI does not, because the compiler tier needs its own Python.
* `--json` (default `tier-report.json`) — written before the summary, including on ordinary test
  failures. This is not an atomic file write; interruption or filesystem errors can prevent a complete report.
* `--quiet` and `--verbose` are one output level and argparse refuses the pair (status 2, nothing run,
  nothing written). Neither flag means the report is not written.

The default invocation prints the table and nothing else on stdout; collection is silent in every
mode, so a directory that cannot be imported is reported as a count and a line rather than as a
traceback storm.

`--only-tier TIER` keeps only the ids that tier owns, as listed in `TIER_TESTS` in `tests/tiers.py`: each
entry names a module, a class or a single method, and an id matches when it equals an entry or begins with
one plus a dot, so `test_a.TestX` never selects `test_a.TestXYZ.test_one`. Filtering happens before
counting, so `collected` is that tier's own share and not the directory's, and a filter that selects
nothing is a collection error and not a green tier. `TIER_TESTS` is the source of the table; the
`skipUnless` gates written in `tests/` are pinned to it by
`tests/test_tiers_single_pass.py::TierFilterTests::test_the_mcp_table_owns_every_mcp_gate_written_in_the_tree`.

## Outcomes

| situation | counted as | table line | exit |
| :-- | :-- | :-- | :-- |
| test passed | `ran` | tier tally | 0 |
| `@unittest.skip*` / `SkipTest`, incl. raised by a class fixture | `skips[]` = `{test, reason, category}`; individual test skips also increment `ran` | row under `CATEGORY / TEST ID / REASON`, capped at 40 rows | 0 |
| assertion failure | `failures[]` | `not passed: <id>` | 1 |
| error, incl. `setUpClass`/`tearDownClass` and module fixture errors | `errors[]` | `not passed: <id>` | 1 |
| unimportable test module | `collection_errors[]` **and** `errors[]` | `collection error: <first line>` | 1 |
| `expectedFailure` that failed | `expected_failures[]` | tally only | 0 |
| `expectedFailure` that passed | `unexpected_successes[]` | not in the tally line; in the JSON | 1 |
| start directory that collects nothing | `collection_errors[]` | `collection error: no tests collected from <dir>` | 1 |
| `--quiet` with `--verbose` | nothing at all | — | 2 |

`collected` snapshots discovery before execution; `ran` counts unittest's `startTest` callbacks.
Class/module setup errors or skips can leave `ran` smaller than `collected`. CPython's normal suite
preserves its count after consumption too; counting first makes this contract independent of cleanup.
An explicit zero-collection check prevents an empty directory from passing silently.

A tier is "clean" when it has no failure, no error, no unexpected success and no collection error.
Skips and expected failures never make a run red; a collection error always does.

## Output modes

Tests log JSON lines to stdout all over this repository, so **stdout is captured and discarded while
the suite runs, in every mode** — the table is this process's stdout, and the report is the artifact.
Stderr is left alone in the default and `--quiet` modes (which is also where the bounded tracebacks go
when a tier is red).

`--verbose` runs the suite under `unittest.TextTestRunner(stream=sys.stderr, verbosity=2)` with the
recorder as its result class. That is deliberate: the reporter does not re-implement unittest's
output, it watches the stdlib's own, so what a developer sees with `python -m unittest discover -s
tests -v` and what CI sees are produced by the same code. Per-test `ok` / `FAIL` / `ERROR` /
`skipped '<reason>'` lines appear live, then the tracebacks, then `Ran N tests …` and `OK` /
`FAILED (failures=1, skipped=2)`. The table still follows on stdout, because the table is the part
that answers "on which gate".

Because unittest printed the tracebacks live, `--verbose` does not repeat them: the bounded
`error_traces` block written to stderr exists for the default mode, and both are in the JSON either
way.

## Report shape (schema 1)

`{schema_version, generated_by, only_tier, environment, tiers[], totals, skips[]}`, where `only_tier` is
the tier named by `--only-tier` and is `null` when the run was unfiltered — the schema version stays 1
because every field that existed before keeps its meaning and nothing was renamed. Per tier:
`start_dir`, `collected`, `ran`, `skipped` (a count), `skips` (objects with `test`, `reason`,
`category`), `expected_failures`, `unexpected_successes`, `failures`, `errors`, `error_traces`,
`collection_errors`. `totals` sums those counters across tiers, and the top-level `skips` repeats each
skip with its `start_dir` — that flat list is what you diff between two hosts. Keys are sorted, indent
2, trailing newline, UTF-8.

`category` is a label read off the **decorator's own wording** (`posix-gate`, `windows-gate`,
`optional-dependency`, `other`) — a grouping of text a human wrote, not a claim about the code. The
raw `reason` is always in the JSON beside it, so a bucket is never the only surviving statement of
why something skipped. Anything the keywords do not match lands in `other` and is visible.

`error_traces` is bounded: at most 5 tracebacks, each cut to 1200 characters, prefixed by the test id.
The report is a CI artifact and a test that dumps a whole file into an assertion must not turn a small
JSON into a large one. The live `--verbose` stream is unittest's own and is not bounded — that is the
price of ordinary unittest output, and the same as the `discover -v` command this replaced.

## Python API

* `bootstrap_path()` — puts the repository root on `sys.path`; `python tests/tiers.py` starts with
  `tests/` there and discovery only adds the start directory, so without it the base tier reports
  import errors for the product package instead of running it.
* `run_start_dir(start_dir, verbose=False, only_tier=None) -> TierResult` — discover + run one directory
  once, all of it or only `only_tier`'s ids.
* `build_report(start_dirs, verbose=False, only_tier=None) -> dict` — one tier per directory, plus totals
  and skips, and the `only_tier` the run was given.
* `tier_selectors(only_tier)` / `id_selected(test_id, selectors)` / `select_suite(suite, selectors)` —
  the filter itself: the prefixes from `TIER_TESTS`, the match on a dotted boundary, and a rebuilt suite
  (the discovered one is never edited in place).
* `tier_clean(tier)`, `environment()`, `print_table(report)`, `print_traces(report)`,
  `parse_args(argv)`, `main(argv) -> int`.

`verbose` and `only_tier` are added keywords with defaults, so both call sites that existed before them
(`run_start_dir(d)` and `build_report([...])`) keep working and keep producing the same document.

## Class fixtures, subtests and the callbacks that must not be re-invented

The recorder subclasses `unittest.TextTestResult` and overrides only `addSkip` (to keep the reason
text beside the id). Everything else reaches the stdlib, which is why three awkward outcomes survive
intact:

* **`setUpClass` / `tearDownClass` / `setUpModule` / `tearDownModule` failures** are not reported by
  the test that failed — `TestSuite` files them through an `_ErrorHolder`, whose `id()` is the fixture
  sentence (`setUpClass (test_x.Class)`). The reporter takes ids through `test.id()` with a `str()`
  fallback, so those land in `errors` as fixture-shaped ids instead of disappearing. The tests of a
  class whose `setUpClass` failed are then **not run at all** (`TestSuite.run` skips them once
  `_classSetupFailed` is set), which is why `collected` and `ran` are two separate numbers: a tier
  where `collected` exceeds `ran` and nothing failed is a fixture that stopped the runner, not a
  smaller directory.
* **A `SkipTest` raised inside a class fixture** goes to `addSkip` with the same `_ErrorHolder`, so it
  is counted as a skip with its reason, not as an error.
* **Subtest failures** (`with self.subTest(...)`): `addSubTest` puts the `(subtest, traceback)` pair in
  the result's own `failures`/`errors` lists. Its id includes the parent and subtest parameters,
  so the failing case remains distinguishable in JSON and the table. Sub-successes are not recorded.

`_Recorder` accepts the stdlib's `verbosity`/`durations` plumbing through `*args`/`**kwargs` because
`TextTestResult`'s constructor signature has already changed between releases and `TextTestRunner`
retries construction when it does not match; a reporting tool must not be the thing that breaks when
the stdlib's does.

## CI wiring

Each tier runs once, in its own interpreter and environment, and each writes its own report; all
three uploads are `if: always()` artifacts named `tier-reports`.

| tier | interpreter | command |
| :-- | :-- | :-- |
| base (measured) | `/tmp/lo-base/bin/python`, 3.12, `requirements-test-base.txt` + `coverage==7.16.0`, `mcp` asserted absent | `python -B -m coverage run tests/tiers.py --start-dir tests --json tier-report-base.json --verbose`, then `coverage report --precision=2 --fail-under=76`, then `coverage xml` |
| optional MCP | `/tmp/lo-mcp/bin/python`, `requirements-dev.txt`, `import mcp` asserted | `python -B tests/tiers.py --start-dir tests --only-tier mcp --json tier-report-mcp.json --verbose` |
| locked Sigma compiler | `/tmp/lo-compiler/bin/python`, 3.13, `--require-hashes -r components/control/sigma/compiler.lock` | `python -B tests/tiers.py --start-dir tests/compiler --json tier-report-compiler.json --verbose` |

Everything else about the job is unchanged: the venvs, the dependency and Python pins, the compiler
hash lock, source+branch coverage and the 76 floor, the lint job, triggers, runner labels, the job-level
timeouts (the three suite steps gained step-level `timeout-minutes` — 25, 10, 15 — because act_runner
0.6.1 enforces those and not the job line, see `docs/testing-standards.md`), the `coverage-xml` artifact
and the secret-scan job.

Because the tier command is now the step that fails or passes, exit status matters more than it did:
`coverage run` propagates it, so a red tier still stops the step before `coverage report` — the same
order of events the removed `unittest discover` line gave, and the reason the artifact uploads run
under `always()`.

**Compiler isolation is not a style choice.** `tests/compiler` imports packages that only exist in
the 3.13 hash-locked environment; under the base interpreter it is a `ModuleNotFoundError` collection
error, and that red is the correct answer. The fix is never `tests/__init__.py`, never an exclusion
list, never converting it to a skip: the tiers are separate because their dependency sets are
separate, and the report is what makes an environment's silence readable.

## Testing this tool

`tests/test_tiers.py` and `tests/test_tiers_single_pass.py` build tiny fixtures — one passing module, one gated skip carrying a
reason no real test uses, one failing module, one that cannot be imported, plus the empty-directory
and multi-directory cases — in a fresh temporary directory per test, with unique module stems so two
fixtures can never share a loaded module. It drives `tiers.main()` and reads the JSON back.

It never discovers the real `tests/` from inside a test. The number the tool reports is a number about
other people's tests, and the only way to assert it is to know exactly what went in; recursing into
the repository would also make the reporter's own tests depend on the product importing.
`sys.modules` and `sys.path` are restored on cleanup, because discovery leaves both dirty.

Plain `python -B -m unittest discover -s tests` must keep passing without `coverage` installed —
nothing in `tests/` imports coverage; CI installs it as a tracer, not as a test dependency.

## Limitations / debt

* The report counts and ids only. No durations, no history, no trend, no per-tier coverage floor —
  timing lives in the CI log, not in the artifact, and nothing here measures it.
* Coverage is measured for the base tier only, and `--fail-under` is a CI flag, not a report field
  (see `docs/testing-standards.md` for the historical baseline and why the floor is machine-specific).
* `--start-dir tests --start-dir tests` given twice would run that directory twice; nothing
  de-duplicates argv, and the CI commands do not repeat a directory.
* `category` is keyword matching over human text. A new gate phrased in new words lands in `other`
  until the wording or the keyword list changes — which is the visible failure mode this tool chose
  over guessing.
* The MCP tier's *presence* assertion is `python -c "import mcp"` in the workflow, plus the rule that
  `test_operator.MCPTests` must not skip there. The report shows the skip; the check that it is
  absent is a human reading of the artifact, not a flag in this tool.
* `--verbose` inherits unittest's `warnings.catch_warnings()` handling around the run, so warning
  filters set by a test can leak across tests in a way `unittest -v` already allows.
