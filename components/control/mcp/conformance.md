# MCP tool surface — conformance

**Every runtime row below is `not-run`.** Nothing in this directory has been built, started, curled or
restored; no container has answered `tools/list`. The rows that *are* checked here are the static ones
(rows 9-13), and they were checked in this checkout on 2026-09-10 by
`python -B scripts/check_foundation.py` and the unit suite — a green result on those rows says the shape is
right, and says nothing about whether the image builds or the process serves.

Run this recipe against a throwaway project on a Linux/amd64 container host, with a **different** project
name, different ports and fresh volumes. Never against a running installation.

## 1. Runtime rows

| # | Row | Command | Must show | State |
|---|---|---|---|---|
| 1 | The lock installs hash-locked, for the pinned platform | `docker build -f components/control/mcp/Dockerfile --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" -t local-observe-mcp:dev .` | the build stage's `pip install --require-hashes` resolves **only** from `requirements.lock`; no `Built wheel`, no source download, no PyPI metadata request beyond the 35 named files; the stage exits 0 | **not-run** |
| 2 | The image starts as the unprivileged uid, read-only | `docker compose -f components/control/mcp/compose.yaml --env-file <private env> up -d` then `docker compose exec mcp id -u` | `65532`; `findmnt -no OPTIONS /config` carries `ro`; `docker inspect --format '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}}'` is `true [ALL]`; no volume is mounted anywhere | **not-run** |
| 3 | The healthcheck's positive answer is a refusal | `curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:<LO_MCP_PORT>/mcp` from the host, then `docker inspect` the health | `401`, and `healthy`. A `200` here is the deploy being wrong, and the probe is written to fail on it. **The reasoning is read in code** (`mcp.py::app` gates on the bearer before the SDK sees a byte); the observation is what has not happened | **not-run** |
| 4 | A mounted map serves the map surface | stage `mcp-identities.json` in the policy directory at mode 0600, `POST /mcp` with `tools/list` using a row's `bearer_token`, then with none, with two `Authorization` headers, with a blank one and with a wrong one | one `tools/list` per valid credential; the two valid agents see the **same** list (visibility is not the gate); every invalid variant is one 401 `{"error":"authentication_required"}` and no tool list | **not-run** |
| 5 | Absent capabilities are absent from the list | same, with `LO_CLICKHOUSE_URL` empty and `LO_MCP_INDEX_PATH` empty | `signal_series` and `topology_neighbourhood` are not in the advertised set, and the other eight are. "Present and answering *unconfigured*" is the failure this row watches for | **not-run** |
| 6 | A bad map stops the boot | repeat row 2's `up` with: a `human` row; a duplicated `bearer_token`; a repeated `identity`; a fifth key in a row; a document that is not a list; an empty file; a file over 16 KiB; `LO_MCP_IDENTITIES` and `LO_MCP_TOKEN_FILE` both set; both blank | eight refusals and one refusal apiece, each naming the variable or the row position and **no token value**; the port closed afterwards (`curl` refuses the connection); no traceback containing a credential | **not-run** |
| 7 | Proposal, human approval and trusted runner | Propose as reader/proposer; approve with a separate human identity; request execution as proposer/executor, with and without a configured handoff | Reader/proposer role refusals; no agent approval path; unconfigured execution preserves approval; configured execution returns one queue receipt and never a runner token; trusted runner rechecks binding and dispatches at most once | **not-run** |
| 8 | An unknown `platform_token` is a 401 and not a boot failure | mount a row whose `platform_token` is well-formed but absent from `LO_PLATFORM_CREDENTIALS`; boot, list tools, call `records` | the boot **succeeds** (the map is validated on its own), the tool list arrives, and `records` comes back as the platform's 401 refusal. This row exists to keep nobody "fixing" it into a boot refusal without deciding to (§4 of CONTRACT.md) | **not-run** |
| 9 | Budget, both directions | ask `records` for `limit: 20` against a store with wide rows; send one JSON-RPC message over 64 KiB | the answer refusal is the sentence v0.1 already sent — `Read exceeds evidence budget; use a smaller result limit` — and the oversized request is a 413 with an empty body, refused before the SDK parses | **not-run** |
| 10 | Nothing secret leaked while any of it ran | `grep -R` the deployment directory, the container logs (`docker compose logs mcp`) and the audit export for every `bearer_token` and `platform_token` value used above | zero hits, in every direction. Also: no credential in a `tools/list` schema or description, and no description naming a path, a command or a URL | **not-run** |
| 11 | Teardown leaves nothing | `docker compose ... down` (no `-v`), delete the map | the platform, store, inventory and credentials untouched; the map file is the only artefact the feature ever touched and it is the operator's; nothing here rotated or removed a credential | **not-run** |

## 2. Static rows, checked in this checkout on 2026-09-10

| # | Row | Command | Result |
|---|---|---|---|
| 12 | The manifest passes the product's own gate | `python -B -c "import sys; sys.path.insert(0,'scripts'); import check_foundation as c, pathlib; p=pathlib.Path('components/control/mcp/compose.yaml'); print(c.check_model(c.read_yaml(p), p.parent), c.check_credential_files(c.read_yaml(p)))"` | `[] []` — required image variable, loopback-only publication, read-only binds with `create_host_path: false`, no credential in an environment value, no exception needed |
| 13 | The whole gate is still green with this component in the tree | `python -B scripts/check_foundation.py --json` | `"static_checks": "pass"`, `errors: []`, and `runtime_conformance: not-run` (the scope line in that report is the honest one: no container was started and no host was read) |
| 14 | The component's structure is pinned by a test, not by prose | `python -B -m unittest tests.test_mcp_component` | passes: five artefacts plus `compose.yaml` and the lock; the lock names `mcp==1.29.1` and agrees with `pyproject.toml`'s extra; the Dockerfile's base digest equals the platform's; `mcp` is in `HOST_PUBLISHED_SERVICES` and the only published port is the loopback line; **no shipped example composes this service** |
| 15 | Every hash in the lock equals the bytes PyPI serves | one loop over PyPI's JSON API per pinned package: keep only `bdist_wheel` files whose tags a cp312/linux-x86_64 interpreter can select, `GET` each, `hashlib.sha256` the bytes, compare with that file's declared `digests.sha256` | 35/35 equal on 2026-09-10. The check ran from a throwaway script under `scratch/` (gitignored, deliberately not committed: it is a verification recipe, not product code, and the line above is it). This verifies digests, not resolvability — **it is not row 1** |
| 16 | The two first-party locks agree where they overlap | compare `requirements.lock` with `components/control/platform/requirements.lock` | the ten shared packages agree on version, and every platform digest appears among the hashes listed here (2026-09-10) |

## 3. What this directory makes executable elsewhere

`components/control/platform/conformance.md` §"Agent tool surface and the private overlay (chat integration)" states
the gap in its own words: *"The manifest change alone boots nothing. No `mcp` service exists in any Compose
file in this repository, and the platform image does not carry the SDK … so the surface runs from a source
tree with `pip install -e '.[mcp]'` — or from an image of the operator's own that does. That packaging is
MCP component's `components/control/mcp/`, not this change."*

That sentence is now historical for steps **1 through 9** of that recipe, which become runnable against a
built image instead of a source tree: step 1's `findmnt` check inside the container (`/config` read-only,
`create_host_path: false` — rows 2 and 4 above), step 2's four credential-source refusals (row 6), step 3's
six malformed-map refusals plus the unknown-`platform_token` observation (rows 6 and 8), step 4's
identical tool lists and single 401 (row 4), step 5's provenance and budget (rows 5 and 9), step 6's role
matrix and execution refusal (row 7), step 7's grep (row 10) and step 9's teardown (row 11). Step 8 (the
private overlay stays outside) is not a container recipe and stays as written.

None of it is **run** by this change. This directory removes the excuse; it does not remove the `not-run`
column, and `docs/COMPONENTS.md` keeps the row `partial` for exactly that reason.

## 4. What no row here can prove

* **A real MCP client.** No client library other than the pinned SDK has been pointed at this surface, and
  the healthcheck deliberately never asks whether an authenticated `tools/list` answers — so whether a
  client that insists on an SSE stream, a session id or an `initialize` handshake can drive
  `stateless_http=True, json_response=True` is unmeasured, and is the most likely reason a first real
  integration fails.
* **The §5 acceptance scenario as a host event.** Rows 7 and 8 trace the "Approved action" clauses through
  the pair — and the *human* half of that scenario still needs the operator UI or a `human` credential
  against `/v1/actions/decision`, which is not this container's surface. The unit-tier names for the five
  clauses are in `tests/test_platform_tools.py::ActionPairTests`; naming them is not running them on a
  host.
* **Whether execution ever becomes available.** There is no configuration switch, no flag and no overlay
  that turns `execute_action` into a claim. It is a refusal by design until a trusted runner handoff
  exists, and a conformance row that "makes it pass" by claiming an action would be a broken approval rail,
  not a passing test.
* **Any number.** Memory, CPU, request latency, per-agent fairness and result sizes are unmeasured. This
  component publishes no metric and no budget of its own.
* **Parity with the legacy estate assistant.** §8 of CONTRACT.md is the rule; running such a comparison is
  a separate conformance artefact with its own result, and nothing below has been compared to anything.
