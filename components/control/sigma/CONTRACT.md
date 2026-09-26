# Sigma execution (experimental)

Build-only compiler: CPython 3.13.7, pySigma 1.5.0, ClickHouse backend 1.1.1;
transitive hashes in compiler.lock. Runtime remains Python 3.12 and consumes
reviewed compiled SQL, not Sigma YAML or AI-generated queries. Backend is listed
as testing upstream; this component is not a claim of general Sigma compatibility.

Initial enabled subset: linux/process_creation, Body, Image and CommandLine;
ASCII string contains/startswith/endswith, all, and pySigma boolean conditions.
Unsupported fields, log sources and modifiers fail compilation. Map missing
process fields to NULL, not an empty-string false negative. Event dataset must be
linux.process_creation and resource_id must resolve in declared inventory.

Reference mapping binds directly to signoz_logs.distributed_logs_v2. Queries use
parameterised UTC nanosecond half-open windows, explicit resource/dataset filters,
5-second execution, one-million-row/64-MiB read and 128-MiB query-memory bounds.
Overflow throws: partial results must not establish recovery. Only aggregated
counts are returned. Endpoint credentials require a SELECT-only ClickHouse user
in a real overlay; client readonly=1 is additional protection, not a grant policy.

No rows, missing mapped fields or query failure produce a coverage finding and
do not resolve an existing threat finding. Successful windows produce a threshold
event and count evidence in the platform's durable state. Cursor stores the exact
pending result before intake, retries identical events, and skips completed or
backward-clock windows. The live loop delays evaluation by 30 seconds. Events
arriving after that window was queried are not re-evaluated in v1; multi-window
catch-up, late-arrival policy and correlation rules remain future work.

Own content only: the shipped artifact set is the product's synthetic fixture plus rules re-derived
here (see "Writing a rule here"); no SigmaHQ corpus is bundled or relicensed. Compiled
artifact checksums detect corruption, not malicious authorship. Treat artifacts
as executable configuration: deploy only reviewed/pinned build outputs.

## Deployment and liveness

The runner never exits on a dependency failure: an unreachable ClickHouse or
platform leaves it printing one fixed line and retrying every two seconds forever.
It is therefore **not** a crash-looping container, and `restart: unless-stopped`
must not be read as its health signal.

Liveness is the compose healthcheck, which is stale-file based: the worker is
`unhealthy` when `${LO_SIGMA_CURSOR}` (the container side, `/state/cursor.json`) has
not been rewritten for 300 seconds, and healthy while a completed evaluation window
is landing. A cursor is written only after a successful query, so a downed ClickHouse
or platform shows up as `unhealthy` within five minutes while the process keeps
running and keeps its pending batch. The healthcheck never reports healthy on the
strength of a live process alone.

Inputs: `LO_SIGMA_ARTIFACT_FILE` is the **host** path of the reviewed compiled
artifact; it is bind-mounted read-only and the container sees it as
`LO_SIGMA_ARTIFACT=/config/rule.json`. The runner sizes that file before opening it and refuses one
above `ARTIFACT_MAX_BYTES` (1 MiB in `local_observe/platform/sigma_runner.py`, measured 2026-09-10 at
about 500× the largest committed artifact), so a mounted file that is not a compiled rule — a log, an
image, a sparse file — is refused by name instead of being read whole into the container's 256 MB, the
same bound that caps the overview worker when it reads a whole rule directory (up to 64 files, so at
most 64 MiB opened). The two names are deliberately distinct —
the same variable used for both means the deployment cannot be read without knowing
which side of the mount a value belongs to. The image is never pulled
(`pull_policy: never`) and is pinned to `linux/amd64`, the only platform it is built
and validated for.

Both of the runner's credentials arrive the same way the platform's role list does: as
mounted files, with the environment carrying only their container paths
`LO_CLICKHOUSE_PASSWORD_FILE=/run/secrets/clickhouse-password` and
`LO_PRODUCER_TOKEN_FILE=/run/secrets/producer-token` (the host paths are the same-named
variables in the top-level `secrets:` block). `local_observe.credentials.read_credential`
prefers the file and still accepts the bare `LO_CLICKHOUSE_PASSWORD` /
`LO_PRODUCER_TOKEN` environment value, which is how the staging scripts keep working; when
both are set the file wins and one warning names the variable, never the value. The
ClickHouse user (`LO_CLICKHOUSE_USER`) is a name, not a secret, and stays in the
environment.

## Writing a rule here

detection content (2026-09-09) added this section with the rule content port. What is ported from the source
estate is **the discipline, not the rules**: six rules went in, one rule survived, and the reason the
survivor is trustworthy is the blocks below rather than anything in its predicate. A rule set nobody
has measured is how a pager becomes noise, which is what notification budget exists to prevent.

Every block here is enforced by a job, not by a reviewer's memory: `sigma_compile.authoring` refuses
the artifact, `tests/test_sigma_rules.py` checks every rule file (compiled or not), and
`tests/compiler/test_sigma_content_rules.py` re-checks the claims that need the pinned backend.

| Block | Required | What it must say | Refused when |
|---|---|---|---|
| `id` | yes | one UUID, never reused | it merges two rules' events and cursors (`sigma.<uuid>`) |
| `enabled` | yes | `true` or `false`, exactly | missing or a string: an assumed flag ships a rule nobody approved |
| `why` | yes | what matches, **what it cannot see**, and which host/dataset it presumes | empty or whitespace |
| `measured` | yes | `false_positives` plus the `window`, `population`, `measured_on` and `source` it came from — or `false_positives: null` with a `because:` sentence | a count with no window, a negative or non-integer count, or an unmeasured rule with no stated reason |
| `unshipped` | iff `enabled: false` | `blocker` (`compile`, `construct`, `policy`, `noise`), a prose `reason`, and for `compile`/`construct` the `refusal:` text the gate actually prints | a disabled rule with no reason (a silently dropped rule is not a decision), or a quoted refusal the compiler no longer gives |
| `parameters` | iff the rule needs an operator input | `source`, `empty` (`deny-all` or `refuse-to-build`), `why_empty_is_safe`, optional `lanes` | any value is inline (no admitted key can hold one), or the empty case is permissive |

**Why `measured:` is a block and not a comment.** `rule_sha256` covers the whole file, so editing
`why:` or `measured:` moves `rule_version`, and an existing evaluation cursor refuses a moved binding
instead of drifting. The tuning notes cannot silently diverge from the artifact a deployment runs.

**Operator inputs are declarations until binding exists.** The pure `compile_rule` function validates
and retains the `parameters` block as authoring metadata; it does not resolve inputs or change the
SQL to enforce their empty policies. `deny-all` declares that a future resolver must treat every actor
as unknown when the input is absent; `refuse-to-build` declares that it must refuse the build.
Neither policy is implemented by the runner today. The public `build_gate`, used by the CLI, therefore
refuses every nonempty parameter declaration, including both policies, before it can write a shipping
artifact. Parameter-free rules still build unchanged. The compiler-tier regressions exercise both
missing-input refusals and compare both shipped artifacts with their committed documents.

The identity allowlist port carries only its shape (an `act` lane and a narrower `prompt` lane), not
real logins or values. `board-actor-outside-lane.yaml` declares that input and ships no artifact.

**Anonymisation is a build rule.** synthetic naming placeholders only: `example.test` for names, `10.11.0.0/16` for
any address a reader might copy, `nas`/`probe-1`/`operator` for hosts and users. Three jobs enforce it:
`check_foundation.check_private_references` walks `examples/` and `components/` against `BANNED_TOKENS`
on every change, `tests/test_sigma_rules.py` asserts that same imported list plus an address/domain
shape check over `examples/sigma/` and `components/control/sigma/`, and the compiler admits non-empty
ASCII values only. A rule that names a real host fails CI; it does not wait for a reviewer to notice.

**Key space comes before thresholds.** A rule whose match key includes a number an ephemeral process
chooses — a source port, a request id, a PID — produces a "new" finding for every record, forever. The
source estate met this exactly once and wrote it down: its new-flow firewall rule fired 20 findings on
its first run, all of them ephemeral UDP ports, and became usable only after every port at or above
32768 was collapsed into one bucket, because the identifying thing there is the src/dst/proto triple
and not the number. The sentence to keep is *"a rule that always fires is the same defect as one that
never does"* — and it is invisible in the YAML, so it cannot be caught by reading a diff. What catches
it here is the pair the blocks above force: a `measured:` count taken over a named window and
population, and the `unmeasured` figure `measurement_report` prints for every rule that has none. Before
any rule with an ephemeral component is armed, that component must be bucketed in the rule (or in the
mapping), not filtered in a dashboard afterwards.

**Derivation is written down.** A rule re-derived from the source estate's content carries
`derived_from:` naming its source file and stating that no text, address, login or count was copied.
Measurements quoted from that source stay labelled as quoted inside `why:` and are never entered in
`measured:` — v0.1's numbers are evidence about v0.1's estate, and putting them in a `measured:` block
would turn somebody else's twelve-day count into this rule's precision budget.

**Licence (sigma rule corpus licence).** Nothing under `examples/sigma/` is SigmaHQ-derived. The six re-derived rules take
their *subject* from private estate content, which carries no licence grant and does not ship; the rule
files here are the product's own work, shipped under this product's licence, and `NOTICE` is unchanged
because there is nothing new to notice. If a future rule copies a SigmaHQ rule (DRL-1.1, not OSI), it
arrives fetched and pinned at build time under its own notice and never inside the product's licence
grant, and `NOTICE` moves in the same PR — the SigmaHQ corpus stays unbundled here, as the paragraph
above has always promised.

**Rebuilding one rule**, inside the hash-locked 3.13 environment (never the 3.12 runtime):

```powershell
scratch/sigma-venv/Scripts/python.exe -B local_observe/platform/sigma_compile.py `
    examples/sigma/<rule>.yaml --output examples/sigma/compiled/<rule>.json
```

The CLI refuses a rule whose `enabled` is not `true` or whose `parameters` block is nonempty.
`compile_rule` remains available for authoring validation, which is how the tier proves *why* a
rule is disabled; its output is not shipping approval. Read and save rules as utf-8: `rule_sha256` is a
hash of the decoded text, so a tool
that decodes with the platform locale (cp1252 on Windows) mints a different `rule_version` for
identical bytes — the reason the compiler tier reads every rule with an explicit encoding.

**What is shipped, in one line.** `sigma_runner.measurement_report()` counts the committed artifacts
and how many carry a measured false-positive rate. Read it per deployment — the runner logs it once at
start (`shipped` / `measured` / `unmeasured`, so `docker logs` answers without a query) — or over the
whole tree:

```powershell
.venv/Scripts/python.exe -B -c "from pathlib import Path; from local_observe.platform import sigma_runner as s; print(s.measurement_report(sorted(Path('examples/sigma/compiled').glob('*.json')))['headline'])"
```

As of 2026-09-09 that prints `2 rules shipped, 2 unmeasured`: the product's own synthetic fixture and
one re-derived rule, neither with a measured rate over a population anyone would page about. The
unmeasured count is the number a detection-quality gate should score (corpus eval), and it is deliberately
not smoothed into a percentage.

Primary sources: [backend](https://github.com/clicksiem/pySigma-backend-clickhouse),
[Sigma backend roster](https://sigmahq.io/docs/digging-deeper/backends).
