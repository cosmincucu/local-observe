# Socketpair and asyncio startup diagnostic

`scripts/diagnose_windows_asyncio.py` is an opt-in, standard-library-only probe
for investigating waits in CPython's Windows loopback
`socket.socketpair()` fallback during default event-loop construction, before
the application coroutine starts. The diagnostic distinguishes construction,
coroutine work, Runner shutdown and process exit. It neither establishes the
host cause nor changes the suite, production code, default loop policy or services.

Run it explicitly with the Python interpreter being investigated:

```text
python -B scripts/diagnose_windows_asyncio.py --output scratch/asyncio-probe-new --iterations 250 --timeout 60
```

The output directory must not exist and its parent must exist. Existing evidence
is never overwritten. `--iterations` accepts 1..1000, default 250; `--timeout`
accepts 1..120 seconds per child, default 60. The full diagnostic runs only on
explicit invocation. Importing the module and normal application startup run no
probe; deterministic tests run tiny two-iteration probes to check the diagnostic.

Three fresh children run serially, one attempt each:

1. `socketpair`: create and close the public socket pair repeatedly.
2. `runner-per-iteration`: enter a fresh default `asyncio.Runner`, run an asserted
   no-op coroutine and close the Runner on every iteration.
3. `shared-runner-control`: run the same number of asserted no-op calls through
   one default Runner, then close it.

The third case compares exposure to repeated loop construction. It does not
substitute a Selector loop or patch the socket implementation. The probe uses
`sys._base_executable` when available so a Windows virtual-environment launcher
does not obscure child ownership. Both the parent and direct child interpreter
identities are recorded. This measures the standard library, not optional
packages installed in that virtual environment.

## Receipts and interpretation

The output contains `report.json` and a directory per case with `result.json`,
`markers.jsonl`, `stderr.log` and, when the worker starts, `stacks.log`. Identity
includes Python version/implementation, platform/architecture, executable and
script hashes, working directory, PID/parent PID, default policy and standard
library source paths/hashes. The actual loop class and source identity are
recorded after construction. Script hashes are checked again after execution.
The report does not dump environment variables, tokens or host process lists.

Flushed stage markers identify socket creation, Runner entry, coroutine entry,
return, Runner close and `WORK_COMPLETE`, with sequence, iteration, PID and time.
`RUNNER_ENTER_BEGIN` precedes context entry, where lazy loop construction occurs.
A daemon observer records Python-thread stacks every five seconds, limited to
16 threads and 25 frames each, at most 64 KiB per snapshot and 1 MiB per child.
There is no timed faulthandler watchdog. Fatal faulthandler is enabled by the
interpreter's `-X faulthandler` and retains its stderr file through interpreter
exit, including `atexit` output. Normal file output avoids pipe-drain deadlocks.

`work_complete` and `exit_observed` are separate facts. Success requires the
complete expected marker sequence and iteration count, matching child PID,
unchanged script input and observed zero exit without timeout or interruption.
A child that prints completion but retains a live thread fails on the outer
deadline. A nonzero exit, missing/malformed marker or PID mismatch also fails.
Successful short runs mean only that these bounded probes did not reproduce
the problem; they do not turn earlier failed or interrupted suites into passes.

On deadline or parent interruption, cleanup uses only `kill()` and a five-second
wait on the exact retained `Popen` instance. Its direct-executable spawn is
ownership evidence even before a child marker arrives; a later matching PID
corroborates that evidence. There is no numeric-PID lookup, descendant traversal,
shell kill, permission escalation or alternate cleanup method. A denied kill or
unverified final wait records `cleanup_failed`, stops later cases and returns
nonzero. An interrupted case likewise stops the remaining probes. Log hashes
are final only when `logs_final` is true; a surviving child may still write.
Launch errors are retained as failed case receipts.

## Checks

`tests/test_asyncio_diagnostic.py` runs tiny real stdlib probes and controlled
owned children. It checks completion without exit, a stall before the first
marker, nonzero exit after completion, missing markers, PID mismatch and stderr
written at interpreter exit. Injected process objects independently check launch
failure, denied cleanup, exit races and KeyboardInterrupt without creating an
uncontrolled process. Invalid limits and existing output paths launch nothing.
These tests validate the diagnostic; operators must run and retain real probes
separately when investigating a host.
