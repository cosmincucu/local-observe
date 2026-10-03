# Testing

Run tests from the repository root using isolated environments. The base tier uses Python 3.12
and `requirements-test-base.txt`; it deliberately excludes MCP. The optional tier uses
`requirements-dev.txt`. The Sigma compiler tier uses Python 3.13 and its hash-locked requirements.

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-test-base.txt
.venv/bin/python -B tests/tiers.py --start-dir tests --json tier-report-base.json --verbose
.venv/bin/python -B scripts/check_foundation.py
.venv/bin/python -B scripts/check_public_tree.py
```

Use the equivalent `Scripts/python.exe` path on Windows. Install `requirements-dev.txt` in a
separate environment for lint and optional MCP tests:

```sh
python -m ruff check local_observe tests scripts components examples
python -B tests/tiers.py --start-dir tests --only-tier mcp --json tier-report-mcp.json
```

For the compiler, use a separate Python 3.13 environment:

```sh
python -m pip install --require-hashes -r components/control/sigma/compiler.lock
python -B tests/tiers.py --start-dir tests/compiler --json tier-report-compiler.json
```

The CI configuration runs the base tier once under coverage, the optional MCP subgroup and the
compiler tier. Tier reports distinguish failures, collection errors and platform or dependency
skips. A skip is not acceptance. Empty collection fails. A separate browser job requires the
authenticated action approval and observer investigation review workflows to pass in desktop and
mobile Chromium, including stale submissions, retries, logout races and denied agent roles. Their requests are
handled by the actual platform API in process; it contacts no deployed service. To run it locally,
install the base test requirements and `scripts/requirements-browser.txt` in an isolated environment,
run `python -m playwright install --with-deps chromium`, then
`python -B scripts/check_approval_browser.py`. `LO_TEST_BROWSER` can explicitly select an existing
Chromium executable. The dedicated check fails if the browser test skips. Other component
conformance and browser checks still require their documented environment.

Privacy review covers every tracked path, including documentation, dotfiles and fixtures. Run
`scripts/check_public_tree.py --policy /path/outside/checkout/policy.json` with a private identifier
inventory when preparing a public tree. Keep that policy and its findings outside the repository.
Source scans do not clear Git history, remote URLs, author identities or publication accounts.

GitHub CI scans reachable product history for secrets. Downstream Gitea staging CI scans
the entire committed snapshot and every commit introduced since the PR base or push's
previous commit; without a usable comparison base it scans full history. This permits
staging to retain separately reviewed private history without copying its historical
scan exceptions into public source. Audit that retained history with its approved
policy before the first promotion. Staging CI does not certify it for publication.
