# Bounded local test supervision

`scripts/run_windows_tests.py` runs the unchanged `tests/tiers.py` in one owned
interpreter, with a deadline covering test execution and interpreter teardown.
This is an opt-in local verification command. It changes no product code, asyncio
policy, standard-library socket behavior, test selection, or Linux CI workflow.

Run it with the intended dependency environment:

```powershell
python -B scripts/run_windows_tests.py --output scratch/windows-base-attempt-1 --timeout 1800
```

The output directory must be new, its parent must already exist, and it must be
outside test discovery. `--timeout` is 1–3600 seconds (default 900).
`--start-dir tests/compiler` selects the compiler suite in its separate Python
environment; `--only-tier mcp` selects the stock MCP tier under `tests`.
Each invocation makes one attempt, with no automatic retries.

On Windows, CPython virtual environments normally launch an additional redirector
process. The supervisor instead launches the base interpreter directly and uses
CPython's child-only `__PYVENV_LAUNCHER__` convention to preserve the selected
environment. A startup handshake must match the owned PID, executable, prefixes,
Python version and MCP availability. A mismatch refuses acceptance. Other Python
implementations on Windows refuse; no shared environment or global setting changes.

`run.json` records the selection and fresh run identity; `owned.json` records the
exact process launch. `stdout.log`, `stderr.log`, and periodic `stacks.log` retain
diagnostic output. Stack observation remains armed through interpreter shutdown.
The unchanged reporter writes `tier-report.json`; `completed.json` binds its hash
to this child and run. `supervisor-report.json` separately records clean suite
results, completed work, observed process exit, timeout, interruption and cleanup.
A passing tier report alone cannot make the supervisor pass.

Timeout, interrupted wait, stale/malformed/mismatched report, failed tests, changed
supervisor/reporter bytes, excessive output, or nonzero/unobserved exit is a failed
attempt. The supervisor terminates only its retained direct-interpreter handle and
waits at most five seconds for exit; cleanup denial is retained and has no alternate
kill method. This does not promise cleanup of arbitrary descendants launched by
tests. Logs are final only after observed interpreter exit (or failed launch).
Files exceeding 32 MiB refuse; polling can overshoot the limit, and oversized files
are retained rather than deleted. Final sizes are checked even after a fast exit.

Source identity covers the supervisor and reporter bytes plus interpreter identity,
not a complete working-tree manifest. Freeze the checkout separately when claiming
exact-source validation. Raw logs remain local diagnostic artifacts and can contain
test output; publish selected evidence, not arbitrary file contents.

The Windows investigation captured a sustained block in `socket.accept` while
creating an asyncio self-pipe, before the coroutine could enforce its own deadline.
Product-free controls also showed variable socketpair latency. This supervisor
contains an unbounded local verification wait and distinguishes passing tests from
successful interpreter exit. It does **not** establish or repair the underlying OS
cause, prove every historical stall had that cause, or turn a timeout into a pass.

`tests/test_windows_test_supervisor.py` uses the real stock reporter on synthetic
tests and real owned children. It covers a passing report followed by blocked
teardown, blocked tests and pre-marker startup, interrupted waits, ordinary failures,
stale/altered reports, disappearing inputs, output overflow and denied cleanup.
The interruption test injects `KeyboardInterrupt` at the wait boundary around a
real child; it does not send a console-wide control signal. Neither these fixtures
nor a correctly refused real run substitutes for a completed full-suite pass.
